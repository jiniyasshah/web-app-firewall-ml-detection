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
)

func main() {
	// 1. CONFIGURATION
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://mongo:27017" // Default for Docker
	}
	
	// 2. CONNECT TO MONGODB
	log.Println("Connecting to MongoDB...")
	client, err := ConnectDB(mongoURI)
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer client.Disconnect(context.Background())

	

	// 3. LOAD RULES INITIALY
	// Note: In a real app, you might want to refresh this periodically or on a signal
	rules, err := LoadRulesFromDB(client, "waf", "rules") // Check your actual DB/Coll names
	if err != nil {
		log.Printf("Warning: Could not load rules from DB: %v", err)
	} else {
		log.Printf("Successfully loaded %d rules from MongoDB", len(rules))
	}

	// Setup Proxy
	origin := os.Getenv("ORIGIN_URL")
	if origin == "" {
		origin = "http://origin:3000"
	}
	originURL, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(originURL)
    limiter := NewRateLimiter(100, 1*time.Minute)
	// 4. REQUEST HANDLER
    wafHandler := func(w http.ResponseWriter, r *http.Request) {
		// CLEAN THE IP ADDRESS (Remove the Port)
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// If splitting fails (e.g., no port), fall back to the whole string
			clientIP = r.RemoteAddr
		}

		// Check Rate Limit Status
		limitReached := limiter.IsRateLimited(clientIP)
		
		// Pass the cleaned IP (or limit status) to the WAF
		score, _ := CheckRequest(r, rules, limitReached)

		// Debug Log (Optional: Enable this if you still have issues)
		// log.Printf("IP: %s | Visits: %d | LimitReached: %v", clientIP, len(limiter.visits[clientIP]), limitReached)

		if score >= 15  {
			log.Printf("BLOCKING Request from %s. Score: %d", clientIP, score)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Request Blocked by WAF"))
			return
		}
		proxy.ServeHTTP(w, r)
	}

	http.HandleFunc("/", wafHandler)

	log.Println("Starting Gateway on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}