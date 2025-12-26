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

func main() {
	// 1. CONFIGURATION
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" { mongoURI = "mongodb://mongo:27017" }

	origin := os.Getenv("ORIGIN_URL")
	if origin == "" { origin = "http://origin:3000" }

	mlURL := os.Getenv("ML_URL")
	if mlURL == "" { mlURL = "http://ml_scorer:8000/predict" }

	// 2. CONNECT DB
	log.Println("Connecting to MongoDB...")
	client, err := database.Connect(mongoURI)
	if err != nil { log.Fatal(err) }
	defer client.Disconnect(context.Background())

	// 3. INIT COMPONENTS
	logger.Init(client, "waf")
	
	originURL, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	rateLimiter := limiter.New(100, 1*time.Minute)

	// 4. INIT API HANDLER (Manages Rules, WAF, and Status)
	apiHandler := api.NewAPIHandler(client, proxy, rateLimiter, mlURL, origin)

	// 5. DEFINE ROUTES
	mux := http.NewServeMux()

	// Dashboard Endpoints
	mux.HandleFunc("/api/stream", apiHandler.SSEHandler)
	mux.HandleFunc("/api/logs", apiHandler.LogsHandler)
	mux.HandleFunc("/api/status", apiHandler.SystemStatus)
	
	// Rule Management Endpoints
	mux.HandleFunc("/api/rules", apiHandler.GetRules)         // GET
	mux.HandleFunc("/api/rules/add", apiHandler.AddRule)      // POST
	mux.HandleFunc("/api/rules/toggle", apiHandler.ToggleRule)// POST

	// WAF Traffic Handler (Catch-All)
	mux.HandleFunc("/", apiHandler.WAFHandler)

	// 6. START SERVER
	log.Println("Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}