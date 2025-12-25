package main

import (
	"context"
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

	// Get the ML Service URL from docker-compose
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
	
	// Initialize Logger (for storing attacks)
	logger.Init(client, "waf")

	// ---------------------------------------------------------
	// 3. INIT COMPONENTS
	// ---------------------------------------------------------
	originURL, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	
	// Rate Limiter: 100 requests per 1 Minute per IP
	rateLimiter := limiter.New(100, 1*time.Minute)

	// ---------------------------------------------------------
	// 4. REQUEST HANDLER
	// ---------------------------------------------------------
	wafHandler := func(w http.ResponseWriter, r *http.Request) {
		// A. Get Client IP
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		// B. Rate Limit Check
		// We don't block immediately here; we pass this status to the Rule Engine.
		// (Unless you want a hard block for rate limits, but usually rules handle it)
		limitReached := rateLimiter.IsRateLimited(clientIP)

		// C. Rule-Based Engine
		// Checks regex, headers, and rate limit status against DB rules
		ruleScore, _, ruleBlock := detector.CheckRequest(r, rules, limitReached)

		// D. ML-Based Engine
		// Sends payload to Python service for deep inspection
		isAnomaly, confidence := detector.CheckML(r, mlURL)

		// E. DECISION MAKER
		// Fuse the intelligence from Rules and ML to get a final Verdict
		verdict, reason := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

		// F. ACTION
		switch verdict {
		case detector.Block:
			log.Printf("⛔ BLOCKED IP: %s | Reason: %s | Score: %d | ML: %.2f", clientIP, reason, ruleScore, confidence)
			
			// Log to DB
			logger.LogAttack(clientIP, r.URL.Path, reason, "Blocked", ruleScore, confidence)

			// Send 403 Forbidden
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("WAF Blocked: " + reason))
			return

		case detector.Monitor:
			// Log but Allow (Useful for testing or low-confidence ML)
			log.Printf("⚠️ FLAGGED IP: %s | Reason: %s | Score: %d | ML: %.2f", clientIP, reason, ruleScore, confidence)
			
			// Log to DB
			logger.LogAttack(clientIP, r.URL.Path, reason, "Flagged", ruleScore, confidence)
			
			// Pass to Origin
			proxy.ServeHTTP(w, r)

		case detector.Allow:
			// Perfectly clean traffic
			proxy.ServeHTTP(w, r)
		}
	}

	http.HandleFunc("/", wafHandler)

	log.Println("Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}