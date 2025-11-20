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
	// 1. DB CONNECTION
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" { mongoURI = "mongodb://mongo:27017" }
	
	client, err := database.Connect(mongoURI)
	if err != nil { log.Fatal(err) }
	defer client.Disconnect(context.Background())

	// 2. LOAD & COMPILE RULES
	rules, err := database.LoadRules(client, "waf", "rules")
	if err != nil { log.Printf("Failed to load rules: %v", err) }
	log.Printf("WAF Engine Ready: %d rules loaded", len(rules))

	// 3. INIT COMPONENTS
	originURL, _ := url.Parse(os.Getenv("ORIGIN_URL"))
	if originURL == nil { originURL, _ = url.Parse("http://origin:3000") }
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	
	rateLimiter := limiter.New(100, 1*time.Minute)

	// 4. SERVER
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Utils: Get Clean IP
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" { clientIP = r.RemoteAddr }

		// Check Limits
		isLimited := rateLimiter.IsRateLimited(clientIP)

		// Run WAF
		score, _, forceBlock := detector.CheckRequest(r, rules, isLimited)

		if score >= 15 || forceBlock {
			log.Printf("BLOCK [%s] Score: %d", clientIP, score)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("WAF Blocked"))
			return
		}

		proxy.ServeHTTP(w, r)
	})

	log.Println("Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}