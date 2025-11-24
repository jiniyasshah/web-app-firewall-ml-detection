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
	// 1. CONFIGURATION
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

	// 2. CONNECT DB & LOAD RULES
	log.Println("Connecting to MongoDB...")
	client, err := database.Connect(mongoURI)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	rules, err := database.LoadRules(client, "waf", "rules")
	if err != nil {
		log.Printf("Warning: Rules DB error: %v", err)
	}
	log.Printf("WAF Engine Ready: %d rules loaded", len(rules))
	logger.Init(client, "waf")

	// 3. INIT COMPONENTS
	originURL, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	
	// Limit: 100 requests per 1 Minute
	rateLimiter := limiter.New(100, 1*time.Minute)

// 4. REQUEST HANDLER
	wafHandler := func(w http.ResponseWriter, r *http.Request) {
		// A. Clean IP
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		// B. Rate Limit Check
		limitReached := rateLimiter.IsRateLimited(clientIP)

		// C. Rule-Based Check
		score, _, forceBlock := detector.CheckRequest(r, rules, limitReached)

		if score >= 15 || forceBlock {
			log.Printf("[BLOCK - RULES] IP: %s | Score: %d", clientIP, score)
			
			// 1. Log to DB (Non-blocking usually, but fine here)
			logger.LogAttack(clientIP, r.URL.Path, "Rules", "Blocked", score, 0.0)

			// 2. Send HTTP Response (Order matters!)
			w.WriteHeader(http.StatusForbidden)        // Set 403
			w.Write([]byte("Blocked by WAF Rules"))    // Send Body
			return
		}

		// D. ML-Based Check
		isAnomaly, confidence := detector.CheckML(r, mlURL)

		if isAnomaly {
			log.Printf("[BLOCK - ML] IP: %s | Confidence: %.2f", clientIP, confidence)
			
			// 1. Log to DB
			logger.LogAttack(clientIP, r.URL.Path, "ML Anomaly", "Blocked", 0, confidence)

			// 2. Send HTTP Response
			w.WriteHeader(http.StatusForbidden)               // Set 403
			w.Write([]byte("Blocked by AI Anomaly Detection")) // Send Body
			return
		}

		// E. Forward to Origin
		proxy.ServeHTTP(w, r)
	}

	http.HandleFunc("/", wafHandler)

	log.Println("Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}