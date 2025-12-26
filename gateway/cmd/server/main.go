package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	// ---------------------------------------------------------
	// 1. CONFIGURATION
	// ---------------------------------------------------------
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://mongo:27017"
	}

	origin := os.Getenv("ORIGIN_URL")
	if origin == "" {
		origin = "http://origin:3000"
	}

	mlURL := os.Getenv("ML_URL")
	if mlURL == "" {
		mlURL = "http://ml_scorer:8000/predict"
	}

	// ---------------------------------------------------------
	// 2. CONNECT DB & LOAD RULES
	// ---------------------------------------------------------
	log.Println("Connecting to MongoDB...")
	client, err := database.Connect(mongoURI)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Load WAF Rules from DB
	rules, err := database.LoadRules(client, "waf", "rules")
	if err != nil {
		log.Printf("Warning: Rules DB error: %v", err)
	}
	log.Printf("WAF Engine Ready: %d rules loaded", len(rules))

	// Initialize Logger
	logger.Init(client, "waf")

	// ---------------------------------------------------------
	// 3. INIT COMPONENTS
	// ---------------------------------------------------------
	originURL, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	rateLimiter := limiter.New(100, 1*time.Minute)

	// ---------------------------------------------------------
	// 4. API ENDPOINTS (Dashboard Support)
	// ---------------------------------------------------------

	// [NEW] API: Real-Time Log Stream (SSE)
	http.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		// A. SSE Headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// B. Get the broadcast channel
		logsCh := logger.GetBroadcastChannel()

		// C. Stream Loop
		for {
			select {
			case entry := <-logsCh:
				// Convert log entry to JSON
				data, err := json.Marshal(entry)
				if err != nil {
					continue
				}
				// Write SSE format: "data: {json}\n\n"
				fmt.Fprintf(w, "data: %s\n\n", data)

				// Flush immediately to client
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}

			case <-r.Context().Done():
				// Client disconnected
				return
			}
		}
	})

	// [NEW] API: Historical Logs (Persistence Fix)
	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Fetch last 50 logs from MongoDB
		logs, err := logger.GetRecentLogs(50)
		if err != nil {
			http.Error(w, "Failed to fetch logs", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(logs)
	})

	// ---------------------------------------------------------
	// 5. WAF REQUEST HANDLER
	// ---------------------------------------------------------
	wafHandler := func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		// A. Capture Request Body for Logger/Analysis
		// We read it, then restore it so the Proxy can read it again later.
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		fullReq := logger.FullRequest{
			Method:  r.Method,
			URL:     r.URL.String(),
			Headers: r.Header,
			Body:    string(bodyBytes),
		}

		// B. Rate Limit Check
		limitReached := rateLimiter.IsRateLimited(clientIP)

		// C. Rule-Based Engine
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

		// DETERMINE TRIGGER PAYLOAD (The "Evidence")
		finalTrigger := ""
		if source == "ML Engine" {
			finalTrigger = mlTrigger
		} else if source == "Rule Engine" {
			finalTrigger = rulePayload
		} else {
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