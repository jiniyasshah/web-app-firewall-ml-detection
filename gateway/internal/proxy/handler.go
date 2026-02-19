package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/limiter"
	"web-app-firewall-ml-detection/internal/logger"
	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/service"

	"go.mongodb.org/mongo-driver/bson"
)

// policyKey used for efficient rule lookup
type policyKey struct {
	RuleID   string
	DomainID string
}

type WAFHandler struct {
	Service     *service.WAFService
	Notifier    *service.NotificationService
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter
	DDOSLimiter *limiter.RateLimiter // Tracks Host/Domain name
	Cfg         *config.Config

	UnconfiguredPage []byte
	CaptchaPage      []byte // [NEW] Stores the raw HTML for the captcha

	// [NEW] Store IPs that solved the captcha
	// Key: IP string, Value: Expiration Time
	VerifiedIPs sync.Map

	// Rules Cache
	rulesMutex     sync.RWMutex
	domainRules    map[string][]models.WAFRule
	domainMap      map[string]models.Domain
	globalFallback []models.WAFRule

	// Stats for System Status
	reqCount uint64
	rpm      uint64
}

// [UPDATED] Added captchaPage argument
func NewWAFHandler(svc *service.WAFService, proxy *httputil.ReverseProxy, rl *limiter.RateLimiter, cfg *config.Config, page404 []byte, captchaPage []byte) *WAFHandler {
	ddosLimiter := limiter.New(cfg.DDOSLimit, 1*time.Minute)
	
	// Start background cleanup for Verified IPs (Prevent Memory Leaks)
	h := &WAFHandler{
		Service:          svc,
		Proxy:            proxy,
		RateLimiter:      rl,
		DDOSLimiter:      ddosLimiter,
		Cfg:              cfg,
		UnconfiguredPage: page404,
		CaptchaPage:      captchaPage,
		// Initialize Maps
		domainRules: make(map[string][]models.WAFRule),
		domainMap:   make(map[string]models.Domain),
	}

	// Load rules immediately on startup
	h.ReloadRules()

	// Start Background Stats Ticker
	go h.startStatsTicker()
	
	// Start Background Cleanup for VerifiedIPs cache
	go h.startCacheCleanup()

	return h
}

// [NEW] Cleanup routine for the whitelist
func (h *WAFHandler) startCacheCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		h.VerifiedIPs.Range(func(key, value interface{}) bool {
			if expiry, ok := value.(time.Time); ok && now.After(expiry) {
				h.VerifiedIPs.Delete(key)
			}
			return true
		})
	}
}

// ReloadRules fetches latest config from DB and updates the memory cache
func (h *WAFHandler) ReloadRules() {
	h.rulesMutex.Lock()
	defer h.rulesMutex.Unlock()

	client := h.Service.Mongo

	// 1. Fetch All Data
	allRules, err := database.GetRules(client, bson.M{})
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load rules: %v", err)
		return
	}
	policies, err := database.GetAllPolicies(client)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load policies: %v", err)
		return
	}
	domains, err := database.GetAllDomains(client)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load domains: %v", err)
		return
	}
	dnsRecords, err := database.GetAllDNSRecords(client)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load dns records: %v", err)
		return
	}

	// 2. Build the Domain Map (Host -> Domain Metadata)
	newDomainMap := make(map[string]models.Domain)
	activeDomainsByID := make(map[string]models.Domain)

	for _, d := range domains {
		if d.Status == "active" {
			newDomainMap[d.Name] = d
			activeDomainsByID[d.ID] = d
		}
	}

	// Map Subdomains (CNAME/A records) to their Parent Domain
	for _, r := range dnsRecords {
		if parentDomain, ok := activeDomainsByID[r.DomainID]; ok {
			newDomainMap[r.Name] = parentDomain
		}
	}

	h.domainMap = newDomainMap

	// 3. Separate Global vs Private Rules
	globalRules := []models.WAFRule{}
	privateRules := make(map[string][]models.WAFRule)

	for _, r := range allRules {
		if r.OwnerID == "" {
			globalRules = append(globalRules, r)
		} else {
			privateRules[r.OwnerID] = append(privateRules[r.OwnerID], r)
		}
	}

	// 4. Index Policies for fast lookup
	policyMap := make(map[policyKey]bool)
	for _, p := range policies {
		policyMap[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
	}

	// Helper to check status (Domain Specific > Global > Default True)
	isEnabled := func(ruleID, domainID string, policies map[policyKey]bool) bool {
		if status, exists := policies[policyKey{RuleID: ruleID, DomainID: domainID}]; exists {
			return status
		}
		if status, exists := policies[policyKey{RuleID: ruleID, DomainID: ""}]; exists {
			return status
		}
		return true // Default ON
	}

	// 5. Build Effective Ruleset for each Active Domain
	newDomainRules := make(map[string][]models.WAFRule)

	for _, d := range domains {
		if d.Status != "active" {
			continue
		}

		var effective []models.WAFRule
		
		// A. Global Rules
		for _, r := range globalRules {
			if isEnabled(r.ID, d.ID, policyMap) {
				effective = append(effective, r)
			}
		}
		
		// B. Private Rules
		if userRules, ok := privateRules[d.UserID]; ok {
			for _, r := range userRules {
				if isEnabled(r.ID, d.ID, policyMap) {
					effective = append(effective, r)
				}
			}
		}

		// Assign rules to Root Domain
		newDomainRules[d.Name] = effective

		// Assign rules to Subdomains
		for _, r := range dnsRecords {
			if r.DomainID == d.ID {
				newDomainRules[r.Name] = effective
			}
		}
	}

	h.domainRules = newDomainRules
	h.globalFallback = globalRules

	log.Printf("♻️  Rules Reloaded (Proxy). Active Hosts: %d", len(h.domainMap))
}

func (h *WAFHandler) startStatsTicker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		count := atomic.SwapUint64(&h.reqCount, 0)
		atomic.StoreUint64(&h.rpm, count)
	}
}

func (h *WAFHandler) GetRPM() uint64 {
	return atomic.LoadUint64(&h.rpm)
}

func getRealIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func getHost(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, ":") {
		if hostname, _, err := net.SplitHostPort(host); err == nil {
			return hostname
		}
	}
	return host
}

// [NEW] Helper to render the captcha page with dynamic values
func (h *WAFHandler) serveChallengePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusServiceUnavailable) // 503 so search engines don't index

	host := getHost(r)
	
	// Convert bytes to string for replacement
	page := string(h.CaptchaPage)
	
	// Inject Dynamic Values
	// 1. Domain Name
	page = strings.Replace(page, "{{DOMAIN}}", host, -1)
	// 2. Site Key (From Config)
	page = strings.Replace(page, "{{SITE_KEY}}", h.Cfg.RecaptchaSiteKey, -1)
	// 3. Redirect URL (Original Request)
	page = strings.Replace(page, "{{REDIRECT_TO}}", r.URL.String(), -1)

	w.Write([]byte(page))
}

// [NEW] Helper to verify the POST request from the captcha form
func (h *WAFHandler) handleCaptchaVerification(w http.ResponseWriter, r *http.Request) {
	clientIP := getRealIP(r)
	host := getHost(r)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid Request", http.StatusBadRequest)
		return
	}
	
	token := r.FormValue("g-recaptcha-response")
	redirectTo := r.FormValue("redirect_to")

	if token == "" {
		http.Error(w, "Captcha token missing", http.StatusForbidden)
		return
	}

	// 1. Verify with Google API
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", url.Values{
		"secret":   {h.Cfg.RecaptchaSecret}, // Use Secret from Config
		"response": {token},
		"remoteip": {clientIP},
	})
	
	if err != nil {
		log.Printf("Google API Error: %v", err)
		http.Error(w, "Verification Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 2. Parse Response
	var result struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		http.Error(w, "Invalid Response from Google", http.StatusInternalServerError)
		return
	}

	// 3. SECURITY CRITICAL: Manual Hostname Verification
	cleanHost := strings.Split(host, ":")[0]
	
	if result.Success && strings.EqualFold(result.Hostname, cleanHost) {
		// ✅ SUCCESS
		log.Printf("✅ Captcha Solved: %s on %s", clientIP, result.Hostname)
		
		// Add to whitelist for 30 minutes
		h.VerifiedIPs.Store(clientIP, time.Now().Add(30*time.Minute))
		
		if redirectTo == "" { redirectTo = "/" }
		http.Redirect(w, r, redirectTo, http.StatusFound)
	} else {
		// ❌ FAILED
		log.Printf("⛔ Captcha Fail: IP=%s | ClaimedHost=%s | ActualHost=%s", clientIP, result.Hostname, cleanHost)
		http.Error(w, "Security Check Failed: Domain Mismatch", http.StatusForbidden)
	}
}

func (h *WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// [NEW] 0. INTERCEPT CAPTCHA SUBMISSION
	if r.URL.Path == "/_waf/verify" && r.Method == "POST" {
		h.handleCaptchaVerification(w, r)
		return
	}

	atomic.AddUint64(&h.reqCount, 1)
	clientIP := getRealIP(r)
	host := getHost(r)

	// Buffer Body for Analysis
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// [NEW] 1. Whitelist Check (Did they solve the captcha?)
	if expiry, ok := h.VerifiedIPs.Load(clientIP); ok {
		if time.Now().Before(expiry.(time.Time)) {
			// User is verified, skip DDoS check
			goto StandardChecks
		} else {
			// Expired
			h.VerifiedIPs.Delete(clientIP)
		}
	}

	// [UPDATED] 2. DDoS Protection Check (Volumetric)
	if !h.DDOSLimiter.Allow(host) {
		log.Printf("🔥 Host Under Attack: %s | Serving Captcha to %s", host, clientIP)
		// SERVE CAPTCHA INSTEAD OF BLOCKING
		h.serveChallengePage(w, r)
		return
	}

StandardChecks:

	// 3. Get Rules & Metadata from MEMORY CACHE
	h.rulesMutex.RLock()
	domainInfo, configured := h.domainMap[host]
	rules := h.domainRules[host]
	h.rulesMutex.RUnlock()

	// 4. UNCONFIGURED DOMAIN CHECK
	if !configured {
		log.Printf("⚠️ Unknown Domain: %s. Returning 404.", host)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		if len(h.UnconfiguredPage) > 0 {
			w.Write(h.UnconfiguredPage)
		} else {
			w.Write([]byte("Domain not configured"))
		}
		return
	}

	// 5. Rate Limit Check (Per IP)
	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	// 6. Rule Engine Check
	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, rules, limitReached)

	// 7. ML Engine Check
	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	if !ruleBlock && ruleScore < 15 {
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, bodyBytes, h.Cfg.MLURL)
	}

	// 8. Final Decision
	verdict, reason, source := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

	if mlTag != "" && mlTag != "Normal" && (isAnomaly || confidence > 0.60) {
		triggeredTags = append(triggeredTags, mlTag)
	}

	finalTrigger := rulePayload
	if source == "ML Engine" || (source == "Hybrid" && mlTrigger != "") {
		finalTrigger = mlTrigger
	}

	// Track Stats
	isFlagged := (verdict == detector.Block || verdict == detector.Monitor)
	isBlocked := (verdict == detector.Block)
	h.Service.TrackRequest(domainInfo.ID, isFlagged, isBlocked)

	// 9. Logging & Action
	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[k] = v
	}
	headers["Host"] = []string{host}

	fullReq := models.FullRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: headers,
		Body:    string(bodyBytes),
	}

	switch verdict {
	case detector.Block:
		log.Printf("⛔ BLOCKED IP: %s | Host: %s | Reason: %s", clientIP, host, reason)
		logger.LogAttack(domainInfo.UserID, domainInfo.ID, clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		
		// Trigger Notification
		if h.Notifier != nil {
			h.Notifier.NotifyAttack(domainInfo.UserID, host, reason, clientIP)
		}
		
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))

	case detector.Monitor:
		log.Printf("⚠️ FLAGGED IP: %s | Host: %s", clientIP, host)
		logger.LogAttack(domainInfo.UserID, domainInfo.ID, clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		h.Proxy.ServeHTTP(w, r)

	case detector.Allow:
		h.Proxy.ServeHTTP(w, r)
	}
}