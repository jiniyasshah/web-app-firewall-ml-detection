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
	"web-app-firewall-ml-detection/internal/utils" // [NEW] Import Utils

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

	// [NEW] Initialize Email & Notification Service
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

	// 4. Initialize Services
	// [UPDATED] Pass notificationService to AuthService
	authService := service.NewAuthService(mongoClient, cfg, notificationService) 
	wafService := service.NewWAFService(mongoClient, cfg)
	domainService := service.NewDomainService(mongoClient)
	ruleService := service.NewRuleService(mongoClient)
	dnsService := service.NewDNSService(mongoClient, cfg)

	// 5. Initialize Proxy
	reverseProxy := proxy.NewReverseProxy(wafService, page502)
	wafHandler := proxy.NewWAFHandler(wafService, reverseProxy, rateLimiter, cfg, page404)
	
	// [NEW] Inject Notifier into WAF Handler for security alerts
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