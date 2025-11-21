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

		// B. Rate Limit Check (FIXED: Call once, use variable)
		limitReached := rateLimiter.IsRateLimited(clientIP)

		// Optional: Block immediately if you want Strict Rate Limiting
		// if limitReached {
		//     w.WriteHeader(http.StatusTooManyRequests)
		//     return
		// }

		// C. Rule-Based Check (The Fast Layer)
		// We pass 'limitReached' so the WAF rules can use it (e.g. "Block if SQLi AND RateLimited")
		score, _, forceBlock := detector.CheckRequest(r, rules, limitReached)

		if score >= 15 || forceBlock {
			log.Printf("[BLOCK - RULES] IP: %s | Score: %d", clientIP, score)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Blocked by WAF Rules"))
			return
		}

		// D. ML-Based Check (The Smart Layer)
		// Only check ML if the rules didn't already block it
		isAnomaly, confidence := detector.CheckML(r, mlURL)

		if isAnomaly {
			log.Printf("[BLOCK - ML] IP: %s | Confidence: %.2f", clientIP, confidence)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Blocked by AI Anomaly Detection"))
			return
		}

		// E. Forward to Origin
		proxy.ServeHTTP(w, r)
	}

	http.HandleFunc("/", wafHandler)

	log.Println("Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}