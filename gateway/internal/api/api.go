package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/limiter"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// APIHandler holds all dependencies
type APIHandler struct {
	MongoClient *mongo.Client
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter

	MLURL        string
	OriginURL    string
	WafPublicIP  string // [NEW] The Droplet IP to use for A records
	UnconfiguredPage []byte

	// RULES CACHE
	rulesMutex sync.RWMutex
	// Map[HostName] -> List of Enabled Rules for that specific host
	domainRules map[string][]detector.WAFRule
	// Fallback for requests that don't match a known domain (or direct IP access)
	globalFallback []detector.WAFRule

	// Stats
	reqCount uint64
	rpm      uint64
}

// NewAPIHandler initializes the handler and loads initial rules
func NewAPIHandler(client *mongo.Client, proxy *httputil.ReverseProxy, limiter *limiter.RateLimiter, mlURL, originURL, wafPublicIP string, unconfiguredPage []byte) *APIHandler {
    h := &APIHandler{
        MongoClient:      client,
        Proxy:            proxy,
        RateLimiter:      limiter,
        MLURL:            mlURL,
        OriginURL:        originURL,
        WafPublicIP:      wafPublicIP,
        UnconfiguredPage: unconfiguredPage, // <--- ASSIGN IT
        domainRules:      make(map[string][]detector.WAFRule),
    }
	
	// Load rules immediately on startup
	h.ReloadRules()
	
	// Start stats background ticker
	go h.startStatsTicker()
	
	return h
}

// ReloadRules: The Brain. Merges Global Rules, Private Rules, and Policies.
func (h *APIHandler) ReloadRules() {
	h.rulesMutex.Lock()
	defer h.rulesMutex.Unlock()

	// 1. Fetch All Data
	allRules, err := database.GetRules(h.MongoClient, bson.M{}) 
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load rules: %v", err)
		return
	}

	policies, err := database.GetAllPolicies(h.MongoClient)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load policies: %v", err)
		return
	}

	domains, err := database.GetAllDomains(h.MongoClient)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load domains: %v", err)
		return
	}

	// 2. Separate Global vs Private Rules
	globalRules := []detector.WAFRule{}
	privateRules := make(map[string][]detector.WAFRule)

	for _, r := range allRules {
		if r.OwnerID == "" {
			globalRules = append(globalRules, r)
		} else {
			privateRules[r.OwnerID] = append(privateRules[r.OwnerID], r)
		}
	}

	// 3. Index Policies for fast lookup
	policyMap := make(map[policyKey]bool)
	for _, p := range policies {
		policyMap[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
	}

	// 4. Build Effective Ruleset per Domain
	newDomainRules := make(map[string][]detector.WAFRule)

	for _, d := range domains {
		var effective []detector.WAFRule

		// A. Add Global Rules
		for _, r := range globalRules {
			if isEnabled(r.ID, d.ID, policyMap, true) {
				effective = append(effective, r)
			}
		}

		// B. Add User's Private Rules
		if userRules, ok := privateRules[d.UserID]; ok {
			for _, r := range userRules {
				if isEnabled(r.ID, d.ID, policyMap, true) {
					effective = append(effective, r)
				}
			}
		}

		newDomainRules[d.Name] = effective
	}

	// 5. Update Handler Cache
	h.domainRules = newDomainRules
	h.globalFallback = globalRules

	log.Printf("♻️  Rules Reloaded. Configured %d domains with effective rulesets.", len(h.domainRules))
}

func isEnabled(ruleID, domainID string, policies map[policyKey]bool, def bool) bool {
	if status, exists := policies[policyKey{RuleID: ruleID, DomainID: domainID}]; exists {
		return status
	}
	if status, exists := policies[policyKey{RuleID: ruleID, DomainID: ""}]; exists {
		return status
	}
	return def
}

func (h *APIHandler) startStatsTicker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		count := atomic.SwapUint64(&h.reqCount, 0)
		atomic.StoreUint64(&h.rpm, count)
	}
}

// WriteJSONError is a utility to return standardized JSON errors
func (h *APIHandler) WriteJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": message,
	})
}