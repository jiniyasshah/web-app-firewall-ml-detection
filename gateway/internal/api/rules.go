package api

import (
	"encoding/json"
	"log"
	"net/http"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/pkg/middleware"
	"web-app-firewall-ml-detection/pkg/response"

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
	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}
	
	domainID := r.URL.Query().Get("domain_id")

	// 1.Fetch only Global Rules (OwnerID is empty/null)
	rules, err := database.GetRules(h.MongoClient, bson.M{
		"$or": []bson.M{
			{"owner_id": ""},
			{"owner_id": bson.M{"$exists": false}},
		},
	})
	if err != nil {
		response.InternalServerError(w, "Failed to fetch rules")
		return
	}

	// 2.Fetch only THIS user's policies
	policies, err := database.GetPoliciesByUser(h.MongoClient, userID)
	if err != nil {
		response.InternalServerError(w, "Failed to fetch policies")
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

	response.JSON(w, rules, http.StatusOK)
}

// --- 2.CUSTOM RULES (User Managed) ---

func (h *APIHandler) GetCustomRules(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}
	
	domainID := r.URL.Query().Get("domain_id")

	// 1.Fetch only Custom Rules owned by this user
	rules, err := database.GetRules(h.MongoClient, bson.M{"owner_id": userID})
	if err != nil {
		response.InternalServerError(w, "Failed to fetch rules")
		return
	}

	// 2.Fetch policies
	policies, err := database.GetPoliciesByUser(h.MongoClient, userID)
	if err != nil {
		response.InternalServerError(w, "Failed to fetch policies")
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

	response.JSON(w, rules, http.StatusOK)
}

func (h *APIHandler) AddCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.MethodNotAllowed(w)
		return
	}

	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}

	var rule detector.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		response.BadRequest(w, "Invalid JSON")
		return
	}

	// Securely force the OwnerID
	rule.OwnerID = userID

	// Set defaults
	if rule.OnMatch.ScoreAdd == 0 && !rule.OnMatch.HardBlock {
		rule.OnMatch.ScoreAdd = 5
	}

	if err := database.AddRule(h.MongoClient, rule); err != nil {
		response.InternalServerError(w, err.Error())
		return
	}

	h.ReloadRules()
	response.Created(w, nil, "Custom rule created")
}

func (h *APIHandler) DeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		response.MethodNotAllowed(w)
		return
	}

	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}
	
	ruleID := r.URL.Query().Get("id")

	if ruleID == "" {
		response.BadRequest(w, "Missing Rule ID")
		return
	}

	if err := database.DeleteRule(h.MongoClient, ruleID, userID); err != nil {
		response.Forbidden(w, "Cannot delete rule: "+err.Error())
		return
	}

	h.ReloadRules()
	response.Success(w, nil, "Rule deleted")
}

// --- 3.SHARED ACTIONS ---

func (h *APIHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.MethodNotAllowed(w)
		return
	}

	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}

	var payload struct {
		ID       string `json:"id"`
		DomainID string `json:"domain_id"`
		Enabled  bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		response.BadRequest(w, "Invalid JSON")
		return
	}

	if payload.ID == "" {
		response.BadRequest(w, "Missing 'id'")
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
		response.InternalServerError(w, "Failed to update policy")
		return
	}

	h.ReloadRules()
	response.Success(w, map[string]interface{}{
		"id":      payload.ID,
		"enabled": payload.Enabled,
	}, "Rule status updated")
}