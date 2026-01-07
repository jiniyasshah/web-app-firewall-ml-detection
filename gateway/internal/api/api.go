// type: uploaded file
// fileName: jiniyasshah/web-app-firewall-ml-detection/web-app-firewall-ml-detection-test/gateway/internal/api/api.go
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
type policyKey struct {
	RuleID   string
	DomainID string
}


type APIHandler struct {
	MongoClient *mongo.Client
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter

	MLURL            string
	OriginURL        string
	WafPublicIP      string
	UnconfiguredPage []byte

	// RULES CACHE
	rulesMutex sync.RWMutex
	domainRules map[string][]detector.WAFRule
	
	// [NEW] Domain Metadata Cache (Host -> Domain Info)
	// This allows WAF to know UserID/DomainID without querying DB every request
	domainMap      map[string]detector.Domain 
	
	globalFallback []detector.WAFRule

	// Stats
	reqCount uint64
	rpm      uint64
}

func NewAPIHandler(client *mongo.Client, proxy *httputil.ReverseProxy, limiter *limiter.RateLimiter, mlURL, originURL, wafPublicIP string, unconfiguredPage []byte) *APIHandler {
	h := &APIHandler{
		MongoClient:      client,
		Proxy:            proxy,
		RateLimiter:      limiter,
		MLURL:            mlURL,
		OriginURL:        originURL,
		WafPublicIP:      wafPublicIP,
		UnconfiguredPage: unconfiguredPage,
		domainRules:      make(map[string][]detector.WAFRule),
		domainMap:        make(map[string]detector.Domain), // [NEW]
	}

	h.ReloadRules()
	go h.startStatsTicker()

	return h
}

func (h *APIHandler) WriteJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": message,
	})
}

// ReloadRules: Merges Rules and Updates Domain Cache
// ... (lines 1-76 remain the same)

// ReloadRules: Merges Rules and Updates Domain Cache
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
	// [NEW] Fetch all DNS Records (Subdomains)
	dnsRecords, err := database.GetAllDNSRecords(h.MongoClient)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load dns records: %v", err)
		return
	}

	// 2. Build the Domain Map (The Routing Table)
	newDomainMap := make(map[string]detector.Domain)
	
	// Helper map to find Parent Domain by ID
	activeDomainsByID := make(map[string]detector.Domain)

	// A. Add Root Domains (e.g., "lemepush.tech")
	for _, d := range domains {
		if d.Status == "active" {
			newDomainMap[d.Name] = d
			activeDomainsByID[d.ID] = d
		}
	}

	// B. [NEW] Add Subdomains (e.g., "www.lemepush.tech")
	for _, r := range dnsRecords {
		// Only add if the parent domain is Active
		if parentDomain, ok := activeDomainsByID[r.DomainID]; ok {
			// Map the subdomain (r.Name) to the Parent Domain's configuration.
			// This ensures "www" gets the same rules/owner as the root.
			newDomainMap[r.Name] = parentDomain
		}
	}

	h.domainMap = newDomainMap

	// 3. Separate Global vs Private Rules (Existing Logic)
	globalRules := []detector.WAFRule{}
	privateRules := make(map[string][]detector.WAFRule)

	for _, r := range allRules {
		if r.OwnerID == "" {
			globalRules = append(globalRules, r)
		} else {
			privateRules[r.OwnerID] = append(privateRules[r.OwnerID], r)
		}
	}

	// 4. Index Policies (Existing Logic)
	policyMap := make(map[policyKey]bool)
	for _, p := range policies {
		policyMap[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
	}

	// 5. Build Effective Ruleset (Existing Logic)
	newDomainRules := make(map[string][]detector.WAFRule)

	for _, d := range domains {
		if d.Status != "active" {
			continue
		}

		var effective []detector.WAFRule
		// A. Global Rules
		for _, r := range globalRules {
			if isEnabled(r.ID, d.ID, policyMap, true) {
				effective = append(effective, r)
			}
		}
		// B. Private Rules
		if userRules, ok := privateRules[d.UserID]; ok {
			for _, r := range userRules {
				if isEnabled(r.ID, d.ID, policyMap, true) {
					effective = append(effective, r)
				}
			}
		}
		
		// Map rules to the Root Domain Name
		newDomainRules[d.Name] = effective
		
		// [NEW] Also map rules to all Subdomains of this domain
		// This ensures "www" gets the same firewall rules as root.
		for _, r := range dnsRecords {
			if r.DomainID == d.ID {
				newDomainRules[r.Name] = effective
			}
		}
	}

	h.domainRules = newDomainRules
	h.globalFallback = globalRules

	log.Printf("♻️  Rules Reloaded. Routing active for %d hosts.", len(h.domainMap))
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