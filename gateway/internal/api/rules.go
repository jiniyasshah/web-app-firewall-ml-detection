package api

import (
	"encoding/json"
	"net/http"
	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils"
)

type WAFEngine interface {
	ReloadRules()
}

type RuleHandler struct {
	Service *service.RuleService
	WAF     WAFEngine
}

func NewRuleHandler(s *service.RuleService, waf WAFEngine) *RuleHandler {
	return &RuleHandler{
		Service: s,
		WAF:     waf,
	}
}

func (h *RuleHandler) GetGlobal(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	rules, err := h.Service.GetGlobalRules(userID, domainID)
	if err != nil {
		utils.WriteError(w, "Failed to fetch global rules", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, rules, http.StatusOK)
}


func (h *RuleHandler) GetCustom(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	rules, err := h.Service.GetCustomRules(userID, domainID)
	if err != nil {
		utils.WriteError(w, "Failed to fetch custom rules", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, rules, http.StatusOK)
}

func (h *RuleHandler) AddCustom(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var rule models.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}
	rule.OwnerID = userID
	if err := h.Service.AddCustomRule(rule); err != nil {
		utils.WriteError(w, "Failed to add rule", http.StatusInternalServerError)
		return
	}
    go h.WAF.ReloadRules()

	utils.WriteMessage(w, "Rule added", http.StatusCreated)
}


func (h *RuleHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var input models.PolicyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if input.RuleID == "" {
		utils.WriteError(w, "Rule ID required", http.StatusBadRequest)
		return
	}

	if err := h.Service.ToggleRule(input, userID); err != nil {
		utils.WriteError(w, "Failed to toggle rule", http.StatusInternalServerError)
		return
	}

	go h.WAF.ReloadRules()
    
	utils.WriteMessage(w, "Rule updated", http.StatusOK)
}