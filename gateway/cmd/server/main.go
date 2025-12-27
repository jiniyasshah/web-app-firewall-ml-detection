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

// [NEW] CORS Middleware
// This wraps the entire router to handle Preflight (OPTIONS) and set headers
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Allow the Frontend Origin
		// In production, change this to your actual domain or use os.Getenv("FRONTEND_URL")
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3001")

		// 2. Allow Credentials (Cookies) - CRITICAL for Auth
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// 3. Allowed Methods
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		// 4. Allowed Headers (Content-Type for JSON, Authorization if using Bearer)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		// 5. Handle Preflight (OPTIONS) requests immediately
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

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

	mlURL := os.Getenv("ML_URL")
	if mlURL == "" {
		mlURL = "http://ml_scorer:8000/predict"
	}

	// 2. CONNECT DB
	log.Println("Connecting to MongoDB...")
	client, err := database.Connect(mongoURI)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// 3. INIT COMPONENTS
	logger.Init(client, "waf")

	originURL, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	rateLimiter := limiter.New(100, 1*time.Minute)

	// 4. INIT API HANDLER
	apiHandler := api.NewAPIHandler(client, proxy, rateLimiter, mlURL, origin)

	// 5. DEFINE ROUTES
	mux := http.NewServeMux()

	// --- PUBLIC ENDPOINTS ---
	mux.HandleFunc("/api/status", apiHandler.SystemStatus)
	mux.HandleFunc("/api/auth/register", apiHandler.Register)
	mux.HandleFunc("/api/auth/login", apiHandler.Login)
	mux.HandleFunc("/api/auth/logout", apiHandler.Logout) // Don't forget Logout!
    mux.HandleFunc("/api/auth/check", api.AuthMiddleware(apiHandler.CheckAuth))
	
	// Stream (Keep public or secure as needed)
	mux.HandleFunc("/api/stream", apiHandler.SSEHandler)

	// --- PROTECTED ENDPOINTS (Wrapped with AuthMiddleware) ---
	
	// Domain Management
	mux.HandleFunc("/api/domains", api.AuthMiddleware(apiHandler.ListDomains))
	mux.HandleFunc("/api/domains/add", api.AuthMiddleware(apiHandler.AddDomain))
	
// [UPDATED] Rules Management
	// Global (Fetch + Toggle)
	mux.HandleFunc("/api/rules/global", api.AuthMiddleware(apiHandler.GetGlobalRules))
	
	// Custom (Fetch + Add + Delete)
	mux.HandleFunc("/api/rules/custom", api.AuthMiddleware(apiHandler.GetCustomRules))
	mux.HandleFunc("/api/rules/custom/add", api.AuthMiddleware(apiHandler.AddCustomRule))
	mux.HandleFunc("/api/rules/custom/delete", api.AuthMiddleware(apiHandler.DeleteCustomRule))
	
	// Shared Toggle (Works for both rule types)
	mux.HandleFunc("/api/rules/toggle", api.AuthMiddleware(apiHandler.ToggleRule))
	
	// Secured Logs
	mux.HandleFunc("/api/logs/secure", api.AuthMiddleware(apiHandler.SecuredLogsHandler))

	// --- WAF TRAFFIC HANDLER (Catch-All) ---
	mux.HandleFunc("/", apiHandler.WAFHandler)

	// 6. START SERVER (With CORS Wrapper)
	log.Println("Gateway running on :8080")
	
	// Wrap the mux with the CORS middleware
	log.Fatal(http.ListenAndServe(":8080", CORSMiddleware(mux)))
}