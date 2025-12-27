package api

import (
	"log"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/limiter"

	"go.mongodb.org/mongo-driver/mongo"
)

// Nameservers for random generation (Used by domains.go)
var nsNames = []string{"alice", "bob", "charlie", "david", "eve", "mallory", "oscar", "peggy", "sybil", "trent"}

// APIHandler holds all dependencies
type APIHandler struct {
	MongoClient *mongo.Client
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter

	MLURL     string
	OriginURL string
	DBName    string
	CollName  string

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

// [FIX] Define policyKey at package level so it is shared between ReloadRules and isEnabled
type policyKey struct {
	RuleID   string
	DomainID string
}

// NewAPIHandler initializes the handler and loads initial rules
func NewAPIHandler(client *mongo.Client, proxy *httputil.ReverseProxy, limiter *limiter.RateLimiter, mlURL, originURL string) *APIHandler {
	h := &APIHandler{
		MongoClient: client,
		Proxy:       proxy,
		RateLimiter: limiter,
		MLURL:       mlURL,
		OriginURL:   originURL,
		DBName:      "waf",
		CollName:    "rules",
		domainRules: make(map[string][]detector.WAFRule),
	}
	h.ReloadRules()
	go h.startStatsTicker()
	return h
}

// ReloadRules: The Brain. Merges Global Rules, Private Rules, and Policies.
func (h *APIHandler) ReloadRules() {
	h.rulesMutex.Lock()
	defer h.rulesMutex.Unlock()

	// 1. Fetch Data
	allRules, err := database.LoadAllRulesRaw(h.MongoClient, h.DBName, h.CollName)
	if err != nil {
		log.Printf("Error loading rules: %v", err)
		return
	}

	policies, err := database.LoadAllPolicies(h.MongoClient, h.DBName)
	if err != nil {
		log.Printf("Error loading policies: %v", err)
		return
	}

	domains, err := database.LoadAllDomains(h.MongoClient, h.DBName)
	if err != nil {
		log.Printf("Error loading domains: %v", err)
		return
	}

	// 2. Separate Global vs Private
	globalRules := []detector.WAFRule{}
	// Map[OwnerID] -> []Rules
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

		// A. Start with Global Rules
		for _, r := range globalRules {
			// Global rules default to TRUE (enabled) unless policy says otherwise
			if isEnabled(r.ID, d.ID, policyMap, true) {
				effective = append(effective, r)
			}
		}

		// B. Add User's Private Rules
		if userRules, ok := privateRules[d.UserID]; ok {
			for _, r := range userRules {
				// Private rules default to TRUE (enabled) unless policy says otherwise
				if isEnabled(r.ID, d.ID, policyMap, true) {
					effective = append(effective, r)
				}
			}
		}

		newDomainRules[d.Name] = effective
	}

	// 5. Update Handler
	h.domainRules = newDomainRules
	h.globalFallback = globalRules // Raw global rules as fallback

	log.Printf("♻️ Rules Reloaded. Configured %d domains.", len(h.domainRules))
}

// Helper to check policy precedence:
// 1. Specific Domain Policy (Does this rule have a setting for this specific domain?)
// 2. "All Domains" Policy (Does this rule have a setting for "all domains" / empty domain_id?)
// 3. Default Value (If no policy exists, what is the default?)
// [FIX] Updated signature to use the package-level policyKey type
func isEnabled(ruleID, domainID string, policies map[policyKey]bool, def bool) bool {
	// Check specific domain policy
	if status, exists := policies[policyKey{RuleID: ruleID, DomainID: domainID}]; exists {
		return status
	}
	// Check generic "all domains" policy (DomainID == "")
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