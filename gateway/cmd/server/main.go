package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/limiter"
	"web-app-firewall-ml-detection/internal/logger"
)

func main() {
	// 1. CONFIGURATION
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" { mongoURI = "mongodb://mongo:27017" }

	origin := os.Getenv("ORIGIN_URL")
	if origin == "" { origin = "http://origin:3000" }

	mlURL := os.Getenv("ML_URL")
	if mlURL == "" { mlURL = "http://ml_scorer:8000/predict" }

	// 2. CONNECT DB & LOAD RULES
	log.Println("Connecting to MongoDB...")
	client, err := database.Connect(mongoURI)
	if err != nil { log.Fatal(err) }
	defer client.Disconnect(context.Background())

	rules, err := database.LoadRules(client, "waf", "rules")
	if err != nil { log.Printf("Warning: Rules DB error: %v", err) }
	log.Printf("WAF Engine Ready: %d rules loaded", len(rules))
	
	logger.Init(client, "waf")

	// 3. INIT COMPONENTS
	originURL, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	rateLimiter := limiter.New(100, 1*time.Minute)

	// 4. REQUEST HANDLER
	wafHandler := func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" { clientIP = r.RemoteAddr }

		// [NEW] Capture Request Body for Logger (and Engines)
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore
		
		fullReq := logger.FullRequest{
			Method:  r.Method,
			URL:     r.URL.String(),
			Headers: r.Header,
			Body:    string(bodyBytes),
		}

		limitReached := rateLimiter.IsRateLimited(clientIP)

		// C. Rule-Based Engine
		// Returns: score, tags, block, combinedPayload
		ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, rules, limitReached)

		var isAnomaly bool
		var confidence float64
		var mlTag string
		var mlTrigger string

		// [OPTIMIZATION] Skip ML if Rule Engine already decided to BLOCK
		shouldSkipML := ruleBlock || ruleScore >= 15

		if !shouldSkipML {
			// D. ML-Based Engine
			isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, mlURL)
		}

		// E. DECISION MAKER
		verdict, reason, source := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

		// MERGE TAGS
		if mlTag != "" && mlTag != "Normal" {
			if isAnomaly || confidence > 0.60 {
				triggeredTags = append(triggeredTags, mlTag)
			}
		}

		// DETERMINE TRIGGER PAYLOAD
		// If Source is ML, use mlTrigger. If Rule, use rulePayload.
		finalTrigger := ""
		if source == "ML Engine" {
			finalTrigger = mlTrigger
		} else if source == "Rule Engine" {
			finalTrigger = rulePayload
		} else {
			// Hybrid or Monitor: Use whichever is available/more interesting
			if mlTrigger != "" {
				finalTrigger = mlTrigger
			} else {
				finalTrigger = rulePayload
			}
		}

		// F. ACTION
		switch verdict {
		case detector.Block:
			log.Printf("⛔ BLOCKED IP: %s | Source: %s | Reason: %s", clientIP, source, reason)
			logger.LogAttack(clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)

			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("WAF Blocked: " + reason))
			return

		case detector.Monitor:
			log.Printf("⚠️ FLAGGED IP: %s | Source: %s | Reason: %s", clientIP, source, reason)
			logger.LogAttack(clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
			proxy.ServeHTTP(w, r)

		case detector.Allow:
			proxy.ServeHTTP(w, r)
		}
	}

	http.HandleFunc("/", wafHandler)
	log.Println("Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}