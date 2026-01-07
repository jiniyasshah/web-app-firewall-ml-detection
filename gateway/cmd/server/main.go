package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"web-app-firewall-ml-detection/internal/api"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/limiter"
	"web-app-firewall-ml-detection/internal/logger"

	"golang.org/x/crypto/acme/autocert"
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
		envOrigins := getEnv("FRONTEND_URL", "https://www.minishield.tech")
		allowedOrigins := strings.Split(envOrigins, ",")
		requestOrigin := r.Header.Get("Origin")

		for _, origin := range allowedOrigins {
			if strings.TrimSpace(origin) == requestOrigin {
				w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
				break
			}
		}

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
	defaultOrigin := getEnv("ORIGIN_URL", "http://origin:3000")
	mlURL := getEnv("ML_URL", "http://ml_scorer:8000/predict")
	wafPublicIP := getEnv("WAF_PUBLIC_IP", "64.227.156.70")

	dnsUser := getEnv("DNS_DB_USER", "pdns")
	dnsPass := getEnv("DNS_DB_PASS", "pdns_password")
	dnsHost := getEnv("DNS_DB_HOST", "dns_sql_db")
	dnsDB := getEnv("DNS_DB_NAME", "powerdns")

	// 2. CONNECT DB (MongoDB)
	log.Println("Connecting to MongoDB...")
	client, err := database.Connect(mongoURI)
	if err != nil {
		log.Fatal("MongoDB Connection failed:", err)
	}
	defer client.Disconnect(context.Background())

	// 3. CONNECT DB (MySQL for DNS)
	log.Println("Connecting to DNS SQL Database...")
	err = database.ConnectDNS(dnsUser, dnsPass, dnsHost, dnsDB)
	if err != nil {
		log.Printf("Warning: DNS DB Connection failed: %v", err)
	}

	// 4. INIT COMPONENTS
	logger.Init(client, "waf")
	rateLimiter := limiter.New(100, 1*time.Minute)

	page404, err := os.ReadFile("pages/404.html")
	if err != nil {
		log.Fatalf("❌ Critical: Could not load pages/404.html: %v", err)
	}

	page502, err := os.ReadFile("pages/502.html")
	if err != nil {
		log.Fatalf("❌ Critical: Could not load pages/502.html: %v", err)
	}

	// 5. REVERSE PROXY LOGIC (Dynamic Origin Switching)
	director := func(req *http.Request) {
		incomingHost := req.Host
		var targetURL *url.URL

		// [UPDATED] Look up Full Record to check OriginSSL Preference
		// NOTE: Ensure database.GetOriginRecord is defined in mongo.go
		record, err := database.GetOriginRecord(client, incomingHost)

		if err == nil && record != nil {
			rawTarget := record.Content
			
			// DYNAMIC SCHEME SELECTION
			// If user set "origin_ssl: true" -> Use HTTPS
			// If not set (false) -> Use HTTP (Legacy behavior)
			if record.OriginSSL {
				if len(rawTarget) < 4 || rawTarget[:4] != "http" {
					rawTarget = "https://" + rawTarget
				}
			} else {
				if len(rawTarget) < 4 || rawTarget[:4] != "http" {
					rawTarget = "http://" + rawTarget
				}
			}

			targetURL, _ = url.Parse(rawTarget)
			log.Printf("[Proxy] Routing %s -> %s (SSL: %v)", incomingHost, rawTarget, record.OriginSSL)
		} else {
			// Fallback if no user record exists
			targetURL, _ = url.Parse(defaultOrigin)
			log.Printf("[Proxy] No user record found for %s, using default: %s", incomingHost, defaultOrigin)
		}

		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Header.Set("X-Forwarded-Host", incomingHost)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Real-IP", req.RemoteAddr)
	}

	// --- DEFINE THE PROXY WITH ERROR HANDLER ---
	proxy := &httputil.ReverseProxy{
		Director: director,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("🔥 Proxy Error for %s: %v", r.Host, err)

			if r.Context().Err() != nil {
				return
			}

			w.WriteHeader(http.StatusBadGateway)
			w.Header().Set("Content-Type", "text/html")
			w.Write(page502)
		},
		// [CRITICAL] Skip SSL verification for Backend
		// We trust our backend IP even if the cert doesn't match the IP address.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 6. INIT API HANDLER
	apiHandler := api.NewAPIHandler(client, proxy, rateLimiter, mlURL, defaultOrigin, wafPublicIP, page404)

	// 7. DEFINE ROUTES
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", apiHandler.SystemStatus)
	mux.HandleFunc("/api/auth/register", apiHandler.Register)
	mux.HandleFunc("/api/auth/login", apiHandler.Login)
	mux.HandleFunc("/api/auth/logout", apiHandler.Logout)
	mux.HandleFunc("/api/auth/check", api.AuthMiddleware(apiHandler.CheckAuth))
	mux.HandleFunc("/api/stream", apiHandler.SSEHandler)
	mux.HandleFunc("/api/domains", api.AuthMiddleware(apiHandler.ListDomains))
	mux.HandleFunc("/api/domains/add", api.AuthMiddleware(apiHandler.AddDomain))
	mux.HandleFunc("/api/domains/verify", api.AuthMiddleware(apiHandler.VerifyDomain))
	mux.HandleFunc("/api/dns/records", api.AuthMiddleware(apiHandler.ManageRecords))
	mux.HandleFunc("/api/rules/global", api.AuthMiddleware(apiHandler.GetGlobalRules))
	mux.HandleFunc("/api/rules/custom", api.AuthMiddleware(apiHandler.GetCustomRules))
	mux.HandleFunc("/api/rules/custom/add", api.AuthMiddleware(apiHandler.AddCustomRule))
	mux.HandleFunc("/api/rules/custom/delete", api.AuthMiddleware(apiHandler.DeleteCustomRule))
	mux.HandleFunc("/api/rules/toggle", api.AuthMiddleware(apiHandler.ToggleRule))
	mux.HandleFunc("/api/logs/secure", api.AuthMiddleware(apiHandler.SecuredLogsHandler))
	mux.HandleFunc("/", apiHandler.WAFHandler)

	// ---------------------------------------------------------
	// 8. HTTPS AUTO-CERT CONFIGURATION
	// ---------------------------------------------------------

	hostPolicy := func(ctx context.Context, host string) error {
		// 1. Allow Admin/Dashboard domains explicitly
		if host == "api.minishield.tech" || host == "test.minishield.tech" || host == "minishield.tech" {
			return nil
		}

		// 2. Allow User Domains & Subdomains
		if database.IsHostAllowed(client, host) {
			return nil
		}

		return fmt.Errorf("host %s not allowed", host)
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache("certs"),
	}

	// HTTPS Server
	httpsServer := &http.Server{
		Addr:    ":443",
		Handler: CORSMiddleware(mux),
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	// ---------------------------------------------------------
	// 9. START SERVERS
	// ---------------------------------------------------------

	go func() {
		log.Println("✅ Starting HTTP Server on :80 (ACME Challenge + Redirect)")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Fatalf("HTTP Server Failed: %v", err)
		}
	}()

	log.Println("🔒 Starting HTTPS WAF on :443")
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS Server Failed: %v", err)
	}
}