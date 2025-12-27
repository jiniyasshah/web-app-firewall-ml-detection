package api

import (
	"encoding/json"
	"net/http"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
)

// AddRuleSecure adds a new rule for a specific user domain
func (h *APIHandler) AddRuleSecure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// In production: Verify user owns the domain specified in rule.DomainID
	userID := r.Context().Value("user_id").(string)
	_ = userID // validation logic placeholder

	var rule detector.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := database.AddRule(h.MongoClient, h.DBName, h.CollName, rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Rule added successfully"})
}

// GetRules fetches Global rules (where domain_id is missing) + Domain specific rules
func (h *APIHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	// 1. Fetch Global Rules
	// We pass "" to indicate we want rules where domain_id DOES NOT exist
	finalRules, err := database.GetAllRules(h.MongoClient, "")
	if err != nil {
		http.Error(w, "Failed to fetch global rules", http.StatusInternalServerError)
		return
	}

	// 2. Fetch Domain Specific Rules (If a valid domain_id is requested)
	if domainID != "" {
		// A. Security Check: Does the domain exist and do I own it?
		domain, err := database.GetDomainByID(h.MongoClient, domainID)
		
		// We only add domain rules if the domain exists AND the user owns it.
		// If the domain is missing (err != nil) or unauthorized, we simply skip this part.
		if err == nil && domain.UserID == userID {
			
			// B. Fetch the specific rules
			domainRules, err := database.GetAllRules(h.MongoClient, domainID)
			if err == nil {
				finalRules = append(finalRules, domainRules...)
			}
		}
	}

	// 3. Return the combined list
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalRules)
}

// ToggleRule enables or disables an existing rule
func (h *APIHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if payload.ID == "" {
		http.Error(w, "Missing Rule ID", http.StatusBadRequest)
		return
	}

	if err := database.ToggleRule(h.MongoClient, h.DBName, h.CollName, payload.ID, payload.Enabled); err != nil {
		http.Error(w, "Failed to toggle rule: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.ReloadRules()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Rule toggle successful"})
}