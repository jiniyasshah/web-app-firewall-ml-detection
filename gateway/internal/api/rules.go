package api

import (
	"encoding/json"
	"log"
	"net/http"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"

	"go.mongodb.org/mongo-driver/bson"
)

// Helper to determine if a rule is enabled based on user policies
func resolveEnabledStatus(ruleID, domainID string, policies map[policyKey]bool, defaultState bool) bool {
	// 1.Check Specific Domain Policy
	if enabled, exists := policies[policyKey{RuleID: ruleID, DomainID: domainID}]; exists {
		return enabled
	}
	// 2.Check Global User Policy (DomainID empty)
	if enabled, exists := policies[policyKey{RuleID: ruleID, DomainID: ""}]; exists {
		return enabled
	}
	// 3.Fallback
	return defaultState
}

// --- 1.GLOBAL RULES (System Managed) ---

func (h *APIHandler) GetGlobalRules(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	// 1.Fetch only Global Rules (OwnerID is empty/null)
	rules, err := database.GetRules(h.MongoClient, bson.M{
		"$or": []bson.M{
			{"owner_id": ""},
			{"owner_id": bson.M{"$exists": false}},
		},
	})
	if err != nil {
		h.WriteJSONError(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}

	// 2.Fetch only THIS user's policies
	policies, err := database.GetPoliciesByUser(h.MongoClient, userID)
	if err != nil {
		h.WriteJSONError(w, "Failed to fetch policies", http.StatusInternalServerError)
		return
	}

	// 3.Map Policies
	userPolicies := make(map[policyKey]bool)
	for _, p := range policies {
		userPolicies[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
	}

	// 4.Hydrate Response
	for i := range rules {
		rules[i].Enabled = resolveEnabledStatus(rules[i].ID, domainID, userPolicies, true)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// --- 2.CUSTOM RULES (User Managed) ---

func (h *APIHandler) GetCustomRules(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	// 1.Fetch only Custom Rules owned by this user
	rules, err := database.GetRules(h.MongoClient, bson.M{"owner_id": userID})
	if err != nil {
		h.WriteJSONError(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}

	// 2.Fetch policies
	policies, err := database.GetPoliciesByUser(h.MongoClient, userID)
	if err != nil {
		h.WriteJSONError(w, "Failed to fetch policies", http.StatusInternalServerError)
		return
	}

	// 3.Map Policies
	userPolicies := make(map[policyKey]bool)
	for _, p := range policies {
		userPolicies[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
	}

	// 4.Hydrate Response
	for i := range rules {
		// Custom rules default to true if no policy exists
		rules[i].Enabled = resolveEnabledStatus(rules[i].ID, domainID, userPolicies, true)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func (h *APIHandler) AddCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	var rule detector.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		h.WriteJSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Securely force the OwnerID
	rule.OwnerID = userID

	// Set defaults
	if rule.OnMatch.ScoreAdd == 0 && !rule.OnMatch.HardBlock {
		rule.OnMatch.ScoreAdd = 5
	}

	if err := database.AddRule(h.MongoClient, rule); err != nil {
		h.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Custom rule created"})
}

func (h *APIHandler) DeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)
	ruleID := r.URL.Query().Get("id")

	if ruleID == "" {
		h.WriteJSONError(w, "Missing Rule ID", http.StatusBadRequest)
		return
	}

	if err := database.DeleteRule(h.MongoClient, ruleID, userID); err != nil {
		h.WriteJSONError(w, "Cannot delete rule: "+err.Error(), http.StatusForbidden)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Rule deleted"})
}

// --- 3.SHARED ACTIONS ---

func (h *APIHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	var payload struct {
		ID       string `json:"id"`
		DomainID string `json:"domain_id"`
		Enabled  bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.WriteJSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if payload.ID == "" {
		h.WriteJSONError(w, "Missing 'id'", http.StatusBadRequest)
		return
	}

	policy := detector.RulePolicy{
		UserID:   userID,
		RuleID:   payload.ID,
		DomainID: payload.DomainID,
		Enabled:  payload.Enabled,
	}

	if err := database.UpsertRulePolicy(h.MongoClient, policy); err != nil {
		log.Printf("[ERROR] Failed to save policy: %v", err)
		h.WriteJSONError(w, "Failed to update policy", http.StatusInternalServerError)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Rule status updated",
		"id":      payload.ID,
		"enabled": payload.Enabled,
	})
}