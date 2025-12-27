package api

import (
	"encoding/json"
	"log"
	"net/http"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
)

// --- 1. GLOBAL RULES (System Managed) ---

func (h *APIHandler) GetGlobalRules(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id") 

	// 1. Load Data
	allRules, err := database.LoadAllRulesRaw(h.MongoClient, h.DBName, h.CollName)
	if err != nil {
		http.Error(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}

	policies, err := database.LoadAllPolicies(h.MongoClient, h.DBName)
	if err != nil {
		http.Error(w, "Failed to fetch policies", http.StatusInternalServerError)
		return
	}

	// 2. Build Policy Map
	userPolicies := make(map[policyKey]bool)
	for _, p := range policies {
		if p.UserID == userID {
			userPolicies[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
		}
	}

	// 3. Filter & Hydrate
	var response []detector.WAFRule
	for _, rule := range allRules {
		// Global Rule Check (OwnerID is empty)
		if rule.OwnerID == "" {
			rule.Enabled = isEnabled(rule.ID, domainID, userPolicies, true)
			response = append(response, rule)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// --- 2. CUSTOM RULES (User Managed) ---

func (h *APIHandler) GetCustomRules(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	allRules, err := database.LoadAllRulesRaw(h.MongoClient, h.DBName, h.CollName)
	if err != nil {
		http.Error(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}

	policies, err := database.LoadAllPolicies(h.MongoClient, h.DBName)
	if err != nil {
		http.Error(w, "Failed to fetch policies", http.StatusInternalServerError)
		return
	}

	userPolicies := make(map[policyKey]bool)
	for _, p := range policies {
		if p.UserID == userID {
			userPolicies[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
		}
	}

	var response []detector.WAFRule
	for _, rule := range allRules {
		// Ownership Check
		if rule.OwnerID == userID {
			rule.Enabled = isEnabled(rule.ID, domainID, userPolicies, true)
			response = append(response, rule)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *APIHandler) AddCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	var rule detector.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// FORCE OwnerID to current user (Private Rule)
	rule.OwnerID = userID
	
	if rule.OnMatch.ScoreAdd == 0 && !rule.OnMatch.HardBlock {
		rule.OnMatch.ScoreAdd = 5 
	}

	if err := database.AddRule(h.MongoClient, h.DBName, h.CollName, rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Custom rule created"})
}

func (h *APIHandler) DeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	userID := r.Context().Value("user_id").(string)
	ruleID := r.URL.Query().Get("id") // Expecting ?id=MONGO_ID

	if ruleID == "" {
		http.Error(w, "Missing Rule ID parameter", http.StatusBadRequest)
		return
	}

	if err := database.DeleteRule(h.MongoClient, h.DBName, h.CollName, ruleID, userID); err != nil {
		http.Error(w, "Cannot delete rule: "+err.Error(), http.StatusForbidden)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Rule deleted"})
}

// --- 3. SHARED ACTIONS ---

// ToggleRule: Toggles ANY rule (Global or Custom) using the MongoDB _id
func (h *APIHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	// CLEANER: Only accept 'id' (which maps to the Mongo _id)
	// We also support '_id' key for convenience if the frontend sends the raw object back.
	var payload struct {
		ID       string `json:"id"`        // Standard JSON API key
		MongoID  string `json:"_id"`       // Alternative (Raw Mongo key)
		DomainID string `json:"domain_id"` // Empty = All my domains
		Enabled  bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Determine the ID
	targetID := payload.ID
	if targetID == "" {
		targetID = payload.MongoID
	}

	if targetID == "" {
		log.Printf("[ERROR] ToggleRule called with empty ID by user %s", userID)
		http.Error(w, "Missing 'id' or '_id' in payload", http.StatusBadRequest)
		return
	}

	// Create/Update Policy referencing the Rule's Mongo ID
	policy := detector.RulePolicy{
		UserID:   userID,
		RuleID:   targetID,
		DomainID: payload.DomainID,
		Enabled:  payload.Enabled,
	}

	log.Printf("[DEBUG] User %s Toggling Rule %s -> %v (Domain: '%s')", userID, targetID, payload.Enabled, payload.DomainID)

	if err := database.UpsertRulePolicy(h.MongoClient, h.DBName, policy); err != nil {
		log.Printf("[ERROR] Failed to save policy: %v", err)
		http.Error(w, "Failed to update policy", http.StatusInternalServerError)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Rule status updated"})
}