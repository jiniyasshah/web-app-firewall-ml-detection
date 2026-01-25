package service

import (
	"log"
	"net/url"
	"sync"
	"time"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type policyKey struct {
	RuleID   string
	DomainID string
}

// statsDelta holds the counts for a specific domain since the last flush
type statsDelta struct {
	Total   int64
	Flagged int64
	Blocked int64
}

type WAFService struct {
	Mongo *mongo.Client
	Cfg   *config.Config

	// Routing Cache
	mu             sync.RWMutex
	domainRules    map[string][]models.WAFRule
	domainMap      map[string]models.Domain
	globalFallback []models.WAFRule

	// Stats Buffer (To prevent hitting DB on every request)
	statsMu     sync.Mutex
	statsBuffer map[string]*statsDelta
}

func NewWAFService(client *mongo.Client, cfg *config.Config) *WAFService {
	s := &WAFService{
		Mongo:       client,
		Cfg:         cfg,
		domainRules: make(map[string][]models.WAFRule),
		domainMap:   make(map[string]models.Domain),
		statsBuffer: make(map[string]*statsDelta),
	}
	
	s.ReloadRules() // Load immediately on startup
	
	// Start the background stats flusher (Runs every 5 seconds)
	go s.startStatsFlusher()
	
	return s
}

// --- STATS LOGIC ---

// TrackRequest buffers the request count in memory
func (s *WAFService) TrackRequest(domainID string, isFlagged bool, isBlocked bool) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	if _, exists := s.statsBuffer[domainID]; !exists {
		s.statsBuffer[domainID] = &statsDelta{}
	}

	s.statsBuffer[domainID].Total++
	if isFlagged {
		s.statsBuffer[domainID].Flagged++
	}
	if isBlocked {
		s.statsBuffer[domainID].Blocked++
	}
}

func (s *WAFService) startStatsFlusher() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.flushStats()
	}
}

func (s *WAFService) flushStats() {
	s.statsMu.Lock()
	if len(s.statsBuffer) == 0 {
		s.statsMu.Unlock()
		return
	}

	// Snapshot and clear buffer to release lock quickly
	snapshot := make(map[string]*statsDelta)
	for k, v := range s.statsBuffer {
		snapshot[k] = v
	}
	s.statsBuffer = make(map[string]*statsDelta)
	s.statsMu.Unlock()

	// Push updates to DB
	for domainID, delta := range snapshot {
		if delta.Total > 0 {
			// This calls the function we added to internal/database/domain_repo.go
			err := database.IncrementDomainStats(s.Mongo, domainID, delta.Total, delta.Flagged, delta.Blocked)
			if err != nil {
				log.Printf("⚠️ Error flushing stats for domain %s: %v", domainID, err)
			}
		}
	}
}

// --- ROUTING LOGIC ---

// GetRoutingInfo returns the rules and domain metadata for a specific host
func (s *WAFService) GetRoutingInfo(host string) ([]models.WAFRule, models.Domain, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules, rulesExist := s.domainRules[host]
	domain, domainExists := s.domainMap[host]

	return rules, domain, rulesExist && domainExists
}

// GetTargetURL determines where to proxy the request
func (s *WAFService) GetTargetURL(incomingHost string) *url.URL {
	// 1. Check DB for specific Origin Record
	record, err := database.GetOriginRecord(s.Mongo, incomingHost)
	if err == nil && record != nil {
		rawTarget := record.Content

		// Dynamic Scheme Selection
		if record.OriginSSL {
			if len(rawTarget) < 4 || rawTarget[:4] != "http" {
				rawTarget = "https://" + rawTarget
			}
		} else {
			if len(rawTarget) < 4 || rawTarget[:4] != "http" {
				rawTarget = "http://" + rawTarget
			}
		}

		u, _ := url.Parse(rawTarget)
		return u
	}

	// 2. Fallback to Default Origin
	u, _ := url.Parse(s.Cfg.OriginURL)
	return u
}

// ReloadRules loads all configurations from DB
func (s *WAFService) ReloadRules() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Fetch All Data
	allRules, err := database.GetRules(s.Mongo, bson.M{})
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load rules: %v", err)
		return
	}
	policies, err := database.GetAllPolicies(s.Mongo)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load policies: %v", err)
		return
	}
	domains, err := database.GetAllDomains(s.Mongo)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load domains: %v", err)
		return
	}
	dnsRecords, err := database.GetAllDNSRecords(s.Mongo)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load dns records: %v", err)
		return
	}

	// 2. Build Domain Map
	newDomainMap := make(map[string]models.Domain)
	activeDomainsByID := make(map[string]models.Domain)

	for _, d := range domains {
		if d.Status == "active" {
			newDomainMap[d.Name] = d
			activeDomainsByID[d.ID] = d
		}
	}

	for _, r := range dnsRecords {
		if parentDomain, ok := activeDomainsByID[r.DomainID]; ok {
			newDomainMap[r.Name] = parentDomain
		}
	}
	s.domainMap = newDomainMap

	// 3. Separate Rules
	globalRules := []models.WAFRule{}
	privateRules := make(map[string][]models.WAFRule)

	for _, r := range allRules {
		if r.OwnerID == "" {
			globalRules = append(globalRules, r)
		} else {
			privateRules[r.OwnerID] = append(privateRules[r.OwnerID], r)
		}
	}

	// 4. Index Policies
	policyMap := make(map[policyKey]bool)
	for _, p := range policies {
		policyMap[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
	}

	// 5. Build Effective Ruleset
	newDomainRules := make(map[string][]models.WAFRule)
	for _, d := range domains {
		if d.Status != "active" {
			continue
		}

		var effective []models.WAFRule
		// Global
		for _, r := range globalRules {
			if s.isEnabled(r.ID, d.ID, policyMap, true) {
				effective = append(effective, r)
			}
		}
		// Private
		if userRules, ok := privateRules[d.UserID]; ok {
			for _, r := range userRules {
				if s.isEnabled(r.ID, d.ID, policyMap, true) {
					effective = append(effective, r)
				}
			}
		}

		newDomainRules[d.Name] = effective
		for _, r := range dnsRecords {
			if r.DomainID == d.ID {
				newDomainRules[r.Name] = effective
			}
		}
	}

	s.domainRules = newDomainRules
	s.globalFallback = globalRules

	log.Printf("♻️  Rules Reloaded. Routing active for %d hosts.", len(s.domainMap))
}

func (s *WAFService) isEnabled(ruleID, domainID string, policies map[policyKey]bool, def bool) bool {
	if status, exists := policies[policyKey{RuleID: ruleID, DomainID: domainID}]; exists {
		return status
	}
	if status, exists := policies[policyKey{RuleID: ruleID, DomainID: ""}]; exists {
		return status
	}
	return def
}