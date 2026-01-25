package proxy

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
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
	Notifier    *service.NotificationService // [NEW] Added this field
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter
	Cfg         *config.Config

	UnconfiguredPage []byte

	// Rules Cache
	rulesMutex     sync.RWMutex
	domainRules    map[string][]models.WAFRule
	domainMap      map[string]models.Domain
	globalFallback []models.WAFRule

	// Stats for System Status
	reqCount uint64
	rpm      uint64
}

func NewWAFHandler(svc *service.WAFService, proxy *httputil.ReverseProxy, rl *limiter.RateLimiter, cfg *config.Config, page404 []byte) *WAFHandler {
	h := &WAFHandler{
		Service:          svc,
		Proxy:            proxy,
		RateLimiter:      rl,
		Cfg:              cfg,
		UnconfiguredPage: page404,
		// Initialize Maps
		domainRules: make(map[string][]models.WAFRule),
		domainMap:   make(map[string]models.Domain),
	}

	// Load rules immediately on startup
	h.ReloadRules()

	// Start Background Stats Ticker for RPM calculation
	go h.startStatsTicker()

	return h
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

func (h *WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&h.reqCount, 1)
	clientIP := getRealIP(r)

	// Buffer Body for Analysis
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	host := getHost(r)

	// 1. Get Rules & Metadata from MEMORY CACHE
	h.rulesMutex.RLock()
	domainInfo, configured := h.domainMap[host]
	rules := h.domainRules[host]
	h.rulesMutex.RUnlock()

	// 2. UNCONFIGURED DOMAIN CHECK
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

	// 3. Rate Limit Check
	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	// 4. Rule Engine Check
	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, rules, limitReached)

	// 5. ML Engine Check
	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	if !ruleBlock && ruleScore < 15 {
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, bodyBytes, h.Cfg.MLURL)
	}

	// 6. Final Decision
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

	// 7. Logging & Action
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
		
		// [NEW] Trigger Notification
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