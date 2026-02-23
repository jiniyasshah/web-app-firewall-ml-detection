package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"web-app-firewall-ml-detection/internal/api"
	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/limiter"
	"web-app-firewall-ml-detection/internal/logger"
	"web-app-firewall-ml-detection/internal/proxy"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	// 1. Load Configuration
	cfg := config.Load()

	// 2. Database Connections
	log.Println("Connecting to MongoDB...")
	mongoClient, err := database.Connect(cfg.MongoURI)
	if err != nil {
		log.Fatal("MongoDB Connection failed:", err)
	}
	defer mongoClient.Disconnect(context.Background())

	log.Println("Connecting to DNS SQL Database...")
	if err := database.ConnectDNS(cfg.DNSUser, cfg.DNSPass, cfg.DNSHost, cfg.DNSName); err != nil {
		log.Printf("Warning: DNS DB Connection failed: %v", err)
	}

	// 3. Init Core Components
	logger.Init(mongoClient, "waf")
	rateLimiter := limiter.New(100, 1*time.Minute)

	// Initialize Email & Notification Service
	emailSender := utils.NewEmailSender(cfg)
	notificationService := service.NewNotificationService(emailSender, mongoClient)

	page404, _ := os.ReadFile("pages/404.html")
	if len(page404) == 0 {
		page404 = []byte("404 Not Found")
	}

	page502, _ := os.ReadFile("pages/502.html")
	if len(page502) == 0 {
		page502 = []byte("502 Bad Gateway")
	}

	captchaPage, _ := os.ReadFile("pages/captcha.html")
	if len(captchaPage) == 0 {
		log.Println("⚠️ Warning: pages/captcha.html not found. DDoS challenges will fail.")
	}

	page403, err := os.ReadFile("pages/403.html")
	if err != nil {
		log.Println("⚠️ Warning: Could not read pages/403.html")
		page403 = []byte("WAF Blocked: Access Denied") // Fallback
	}

	// 4. Initialize Services
	authService := service.NewAuthService(mongoClient, cfg, notificationService) 
	wafService := service.NewWAFService(mongoClient, cfg)
	domainService := service.NewDomainService(mongoClient)
	ruleService := service.NewRuleService(mongoClient)
	dnsService := service.NewDNSService(mongoClient, cfg)

	// 5. Initialize Proxy
	reverseProxy := proxy.NewReverseProxy(wafService, page502)
	wafHandler := proxy.NewWAFHandler(wafService, reverseProxy, rateLimiter, cfg, page404, captchaPage, page403)
	
	// Inject Notifier into WAF Handler for security alerts
	wafHandler.Notifier = notificationService

	// 6. Initialize Handlers
	authHandler := api.NewAuthHandler(authService)
	domainHandler := api.NewDomainHandler(domainService)
	ruleHandler := api.NewRuleHandler(ruleService, wafHandler)
	dnsHandler := api.NewDNSHandler(dnsService)
	logHandler := api.NewLogHandler(mongoClient)
	systemHandler := api.NewSystemHandler(mongoClient, cfg, wafHandler)

	// 7. Router Setup
	mainRouter := api.NewRouter(cfg, wafHandler, authHandler, domainHandler, ruleHandler, dnsHandler, logHandler, systemHandler)

	// 8. HTTPS Auto-Cert Configuration
	hostPolicy := func(ctx context.Context, host string) error {
		if host == "api.minishield.tech" || host == "minishield.tech" {
			return nil
		}
		// Check if the host is configured in our WAF
		_, _, exists := wafService.GetRoutingInfo(host)
		if exists {
			return nil
		}
		return fmt.Errorf("host %s not allowed", host)
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache("certs"),
	}

	// =========================================================
	// [NEW] BACKGROUND TRAFFIC HISTORY WORKER (Runs 24/7)
	// =========================================================
	go func() {
		var prevTotal int64
		var prevThreats int64
		isFirst := true

		ticker := time.NewTicker(5 * time.Second) // Poll every 5 seconds
		for range ticker.C {
			domains, err := database.GetAllDomains(mongoClient) // Fetch current stats
			if err != nil {
				continue
			}

			var currentTotal, currentThreats int64
			for _, d := range domains {
				currentTotal += d.Stats.TotalRequests
				currentThreats += d.Stats.BlockedRequests + d.Stats.FlaggedRequests
			}

			if isFirst {
				prevTotal = currentTotal
				prevThreats = currentThreats
				isFirst = false
				database.RecordTrafficHistory(mongoClient, 0, 0)
				continue
			}

			// Calculate Delta
			deltaTotal := currentTotal - prevTotal
			if deltaTotal < 0 { deltaTotal = 0 }
			
			deltaThreats := currentThreats - prevThreats
			if deltaThreats < 0 { deltaThreats = 0 }

			// Update Previous
			prevTotal = currentTotal
			prevThreats = currentThreats

			// Save to MongoDB
			database.RecordTrafficHistory(mongoClient, deltaTotal, deltaThreats)
		}
	}()
	// =========================================================

	// 9. Start Servers
	go func() {
		log.Println("✅ Starting HTTP Server on :80 (ACME Challenge + Redirect)")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Fatalf("HTTP Server Failed: %v", err)
		}
	}()

	log.Println("🔒 Starting HTTPS WAF on :443")
	httpsServer := &http.Server{
		Addr:      ":443",
		Handler:   mainRouter,
		TLSConfig: &tls.Config{GetCertificate: certManager.GetCertificate},
	}

	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS Server Failed: %v", err)
	}
}