package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"web-app-firewall-ml-detection/internal/api"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/limiter"
	"web-app-firewall-ml-detection/internal/logger"
)

// getEnv handles fallback values for environment variables
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// CORSMiddleware handles Preflight and Headers
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", getEnv("FRONTEND_URL", "http://localhost:3001"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	// 1. CONFIGURATION
	mongoURI := getEnv("MONGO_URI", "mongodb://mongo:27017")
	
	// Default fallback (e.g. Python server) if domain is not found in DB
	defaultOrigin := getEnv("ORIGIN_URL", "http://origin:3000") 
	
	mlURL := getEnv("ML_URL", "http://ml_scorer:8000/predict")
	
	// DNS Database Config
	dnsUser := getEnv("DNS_DB_USER", "pdns")
	dnsPass := getEnv("DNS_DB_PASS", "pdns_password")
	dnsHost := getEnv("DNS_DB_HOST", "dns_sql_db") // Service name from docker-compose
	dnsDB   := getEnv("DNS_DB_NAME", "powerdns")

	// 2. CONNECT DB (MongoDB)
	log.Println("Connecting to MongoDB...")
	client, err := database.Connect(mongoURI)
	if err != nil {
		log.Fatal("MongoDB Connection failed:", err)
	}
	defer client.Disconnect(context.Background())

	// 3. CONNECT DB (MySQL for DNS) - [NEW]
	log.Println("Connecting to DNS SQL Database...")
	err = database.ConnectDNS(dnsUser, dnsPass, dnsHost, dnsDB)
	if err != nil {
		log.Printf("Warning: DNS DB Connection failed (DNS features may not work): %v", err)
	}

	// 4. INIT COMPONENTS
	logger.Init(client, "waf")
	rateLimiter := limiter.New(100, 1*time.Minute)

	// 5. DYNAMIC REVERSE PROXY LOGIC - [MODIFIED]
	// Instead of a SingleHostProxy, we use a Director to route dynamically
	director := func(req *http.Request) {
		incomingHost := req.Host 
		
		// A. Look up the domain in MongoDB to find the Real Origin IP
		domainConfig, err := database.GetDomainByName(client, incomingHost)
		
		var targetURL *url.URL
		
		// B. Decision Logic
		if err == nil && domainConfig.TargetIP != "" {
			// Found in DB: Route to the specific backend IP/URL user configured
			// Assuming TargetIP is stored like "1.2.3.4" or "http://1.2.3.4"
			// If stored without scheme, prepend "http://"
			rawTarget := domainConfig.TargetIP
			// Basic check to add scheme if missing
			if len(rawTarget) > 4 && rawTarget[:4] != "http" {
				rawTarget = "http://" + rawTarget
			}
			targetURL, _ = url.Parse(rawTarget)
		} else {
			// Not found: Fallback to the default origin (Test Server)
			targetURL, _ = url.Parse(defaultOrigin)
		}

		// C. Rewrite Request
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		
		// Pass the original host header so the backend knows who called
		req.Header.Set("X-Forwarded-Host", incomingHost)
	}

	proxy := &httputil.ReverseProxy{Director: director}

	// 6. INIT API HANDLER
	apiHandler := api.NewAPIHandler(client, proxy, rateLimiter, mlURL, defaultOrigin)

	// 7. DEFINE ROUTES
	mux := http.NewServeMux()

	// --- Public API ---
	mux.HandleFunc("/api/status", apiHandler.SystemStatus)
	mux.HandleFunc("/api/auth/register", apiHandler.Register)
	mux.HandleFunc("/api/auth/login", apiHandler.Login)
	mux.HandleFunc("/api/auth/logout", apiHandler.Logout)
	mux.HandleFunc("/api/auth/check", api.AuthMiddleware(apiHandler.CheckAuth))
	mux.HandleFunc("/api/stream", apiHandler.SSEHandler)

	// --- Protected API (Management) ---
	// Domains
	mux.HandleFunc("/api/domains", api.AuthMiddleware(apiHandler.ListDomains))
	mux.HandleFunc("/api/domains/add", api.AuthMiddleware(apiHandler.AddDomain))

	// DNS Records - [NEW ROUTE]
	mux.HandleFunc("/api/dns/records", api.AuthMiddleware(apiHandler.AddRecord))

	// Rules
	mux.HandleFunc("/api/rules/global", api.AuthMiddleware(apiHandler.GetGlobalRules))
	mux.HandleFunc("/api/rules/custom", api.AuthMiddleware(apiHandler.GetCustomRules))
	mux.HandleFunc("/api/rules/custom/add", api.AuthMiddleware(apiHandler.AddCustomRule))
	mux.HandleFunc("/api/rules/custom/delete", api.AuthMiddleware(apiHandler.DeleteCustomRule))
	mux.HandleFunc("/api/rules/toggle", api.AuthMiddleware(apiHandler.ToggleRule))

	// Logs
	mux.HandleFunc("/api/logs/secure", api.AuthMiddleware(apiHandler.SecuredLogsHandler))

	// --- Traffic Handler (Catch-All) ---
	mux.HandleFunc("/", apiHandler.WAFHandler)

	// 8. START SERVER
	port := getEnv("PORT", "8080")
	log.Printf("Gateway running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, CORSMiddleware(mux)))
}