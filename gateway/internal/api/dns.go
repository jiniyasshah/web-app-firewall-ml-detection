package api

import (
	"encoding/json"
	"net/http"
	"os"

	"web-app-firewall-ml-detection/internal/database"
)

type DNSRecordRequest struct {
	DomainID string `json:"domain_id"`
	Name     string `json:"name"`    // "@" for root, "www", "api", etc.
	Type     string `json:"type"`    // "A", "CNAME", "MX", "TXT"
	Content  string `json:"content"` // "1.2.3.4" or target
	TTL      int    `json:"ttl"`     // Optional, default 300
	Proxied  bool   `json:"proxied"` // TRUE = Through WAF, FALSE = Direct
}

// ManageRecords handles GET, POST, DELETE for DNS records
func (h *APIHandler) ManageRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listRecords(w, r)
	case http.MethodPost:
		h. addRecord(w, r)
	case http.MethodDelete:
		h.deleteRecord(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/dns/records
func (h *APIHandler) addRecord(w http.ResponseWriter, r *http.Request) {
	var req DNSRecordRequest
	if err := json.NewDecoder(r. Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 1. Validate required fields
	if req.DomainID == "" || req.Type == "" || req. Content == "" {
		http.Error(w, "domain_id, type, and content are required", http.StatusBadRequest)
		return
	}

	// 2. Fetch the domain to verify ownership
	domain, err := database.GetDomainByID(h.MongoClient, req.DomainID)
	if err != nil {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// 3. Security:  Ensure the user owns this domain
	userID := r.Context().Value("user_id").(string)
	if domain. UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 4. Check domain is verified
	if domain.Status != "active" {
		http.Error(w, "Domain must be verified before adding records", http.StatusBadRequest)
		return
	}

	// 5. Build the full record name
	recordName := domain.Name
	if req.Name != "" && req.Name != "@" {
		recordName = req.Name + "." + domain.Name
	}

	// 6. Get WAF Public IP
	wafIP := os.Getenv("WAF_PUBLIC_IP")
	if wafIP == "" {
		wafIP = "139.59.76.127"
	}

	// 7. Default TTL
	if req.TTL == 0 {
		req.TTL = 300
	}

	// 8. Add to PowerDNS (MySQL)
	err = database.AddDNSRecord(recordName, req.Type, req.Content, req. Proxied, wafIP)
	if err != nil {
		http.Error(w, "DNS Database Error:  "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 9. Store in MongoDB for internal routing (only for A records when proxied)
	if req.Type == "A" && req.Proxied {
		err = database.AddRoutingRecord(h.MongoClient, req.DomainID, recordName, req.Content)
		if err != nil {
			http.Error(w, "Routing Database Error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "success",
		"message": "DNS record added successfully",
		"record":  map[string]interface{}{
			"name":    recordName,
			"type":    req.Type,
			"content": req. Content,
			"proxied": req. Proxied,
			"ttl":     req. TTL,
		},
	})
}

// GET /api/dns/records? domain_id=xxx
func (h *APIHandler) listRecords(w http.ResponseWriter, r *http.Request) {
	domainID := r. URL.Query().Get("domain_id")
	if domainID == "" {
		http.Error(w, "domain_id is required", http.StatusBadRequest)
		return
	}

	// 1. Verify ownership
	domain, err := database. GetDomainByID(h.MongoClient, domainID)
	if err != nil {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	userID := r.Context().Value("user_id").(string)
	if domain. UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 2. Get records from PowerDNS
	records, err := database.GetDNSRecordsByDomain(domain.Name)
	if err != nil {
		http.Error(w, "Failed to fetch records: "+err. Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

// DELETE /api/dns/records? domain_id=xxx&record_id=yyy
func (h *APIHandler) deleteRecord(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL. Query().Get("domain_id")
	recordID := r.URL.Query().Get("record_id")

	if domainID == "" || recordID == "" {
		http.Error(w, "domain_id and record_id are required", http.StatusBadRequest)
		return
	}

	// 1. Verify ownership
	domain, err := database.GetDomainByID(h.MongoClient, domainID)
	if err != nil {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 2. Delete from PowerDNS (MySQL)
	err = database.DeleteDNSRecord(recordID)
	if err != nil {
		http.Error(w, "Failed to delete record: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Also remove from routing collection if it exists
	err = database.DeleteRoutingRecord(h.MongoClient, recordID)
	if err != nil {
		// Log but don't fail - routing record might not exist
		// log.Printf("Warning: Could not delete routing record:  %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"message": "Record deleted successfully",
	})
}