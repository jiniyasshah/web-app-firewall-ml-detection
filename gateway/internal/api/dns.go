package api

import (
	"encoding/json"
	"net/http"

	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils"
)

type DNSHandler struct {
	Service *service.DNSService
}

func NewDNSHandler(s *service.DNSService) *DNSHandler {
	return &DNSHandler{Service: s}
}

// ManageRecords handles GET, POST, PUT, DELETE for DNS records
func (h *DNSHandler) ManageRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listRecords(w, r)
	case http.MethodPost:
		h.addRecord(w, r)
	case http.MethodPut:
		h.updateRecord(w, r)
	case http.MethodDelete:
		h.deleteRecord(w, r)
	default:
		utils.WriteError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *DNSHandler) listRecords(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	if domainID == "" {
		utils.WriteError(w, "domain_id is required", http.StatusBadRequest)
		return
	}

	records, err := h.Service.GetRecords(domainID, userID)
	if err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}
	utils.WriteSuccess(w, records, http.StatusOK)
}

func (h *DNSHandler) addRecord(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	// [FIXED] Changed database.DNSRecord -> models.DNSRecord
	var req models.DNSRecord
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Basic check before service call
	if req.DomainID == "" || req.Type == "" || req.Content == "" {
		utils.WriteError(w, "domain_id, type, and content are required", http.StatusBadRequest)
		return
	}

	newRecord, err := h.Service.AddRecord(req, userID)
	if err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, map[string]interface{}{
		"status":  "success",
		"message": "DNS record added successfully",
		"record":  newRecord,
	}, http.StatusCreated)
}

func (h *DNSHandler) updateRecord(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	recordID := r.URL.Query().Get("record_id")

	if recordID == "" {
		utils.WriteError(w, "record_id is required", http.StatusBadRequest)
		return
	}

	// [FIXED] Use models.DNSUpdateRequest
	var req models.DNSUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	result, err := h.Service.UpdateRecord(recordID, userID, req)
	if err != nil {
		utils.WriteError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.WriteSuccess(w, map[string]interface{}{
		"status":  "success",
		"message": "Record updated",
		"updates": result,
	}, http.StatusOK)
}

func (h *DNSHandler) deleteRecord(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	recordID := r.URL.Query().Get("record_id")

	if recordID == "" {
		utils.WriteError(w, "record_id is required", http.StatusBadRequest)
		return
	}

	if err := h.Service.DeleteRecord(recordID, userID); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, map[string]string{
		"status":  "success",
		"message": "Record deleted successfully",
	}, http.StatusOK)
}