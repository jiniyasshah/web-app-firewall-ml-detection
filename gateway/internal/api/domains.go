package api

import (
	"encoding/json"
	"net/http"

	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils"
)

type DomainHandler struct {
	Service *service.DomainService
}

func NewDomainHandler(s *service.DomainService) *DomainHandler {
	return &DomainHandler{Service: s}
}

func (h *DomainHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domains, err := h.Service.ListDomains(userID)
	if err != nil {
		utils.WriteError(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, domains, http.StatusOK)
}

func (h *DomainHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var input models.DomainInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	domain, err := h.Service.AddDomain(input, userID)
	if err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, domain, http.StatusCreated)
}

func (h *DomainHandler) Verify(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	domainID := r.URL.Query().Get("id")
	if domainID == "" {
		utils.WriteError(w, "Missing domain id", http.StatusBadRequest)
		return
	}

	success, details, err := h.Service.VerifyDomainOwner(domainID, userID)
	if err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if success {
		utils.WriteSuccess(w, map[string]string{
			"status":  "active",
			"message": "Domain successfully verified! You are now the owner.",
		}, http.StatusOK)
	} else {
		// Verification failed but no system error (nameservers didn't match)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "pending_verification",
			"message": "Verification failed. Nameservers do not match.",
			"details": details,
		})
	}
}

func (h *DomainHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	
	domainID := r.URL.Query().Get("id")
	if domainID == "" {
		utils.WriteError(w, "Missing domain id", http.StatusBadRequest)
		return
	}

	if err := h.Service.DeleteDomain(domainID, userID); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, map[string]string{
		"message": "Domain and all associated records deleted successfully",
	}, http.StatusOK)
}