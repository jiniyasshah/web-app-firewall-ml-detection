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
		h.addRecord(w, r)
	case http.MethodDelete:
		h.deleteRecord(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/dns/records
func (h *APIHandler) addRecord(w http.ResponseWriter, r *http.Request) {
	var req DNSRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 1.Validate required fields
	if req.DomainID == "" || req.Type == "" || req.Content == "" {
		http.Error(w, "domain_id, type, and content are required", http.StatusBadRequest)
		return
	}

	// 2.Fetch the domain to verify ownership
	domain, err := database.GetDomainByID(h.MongoClient, req.DomainID)
	if err != nil {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// 3.Security:  Ensure the user owns this domain
	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 4.Check domain is verified
	if domain.Status != "active" {
		http.Error(w, "Domain must be verified before adding records", http.StatusBadRequest)
		return
	}

	// 5.Build the full record name
	recordName := domain.Name
	if req.Name != "" && req.Name != "@" {
		recordName = req.Name + "." + domain.Name
	}

	// 6.Get WAF Public IP
	wafIP := os.Getenv("WAF_PUBLIC_IP")
	if wafIP == "" {
		wafIP = "139.59.76.127"
	}

	// 7.Default TTL
	if req.TTL == 0 {
		req.TTL = 300
	}

	// 8.Add to MongoDB (Source of Truth for User Display)
	newRecord := database.DNSRecord{
		DomainID: req.DomainID,
		Name:     recordName,
		Type:     req.Type,
		Content:  req.Content, // Store the ORIGIN IP
		TTL:      req.TTL,
		Proxied:  req.Proxied,
	}

	recordID, err := database.CreateDNSRecord(h.MongoClient, newRecord)
	if err != nil {
		http.Error(w, "Database Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	newRecord.ID = recordID

	// 9.Add to PowerDNS (Resolution Backend)
	// database.AddPowerDNSRecord handles the proxied logic internally (swapping content for WAF IP)
	err = database.AddPowerDNSRecord(recordName, req.Type, req.Content, req.Proxied, wafIP)
	if err != nil {
		// Rollback MongoDB if PowerDNS fails? For now just error.
		http.Error(w, "DNS Propagation Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Note: We no longer need separate Routing records.
	// The WAF should lookup the Origin IP from the dns_records collection.

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "DNS record added successfully",
		"record":  newRecord, // Return the clean record with ID
	})
}

// GET /api/dns/records? domain_id=xxx
func (h *APIHandler) listRecords(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	if domainID == "" {
		http.Error(w, "domain_id is required", http.StatusBadRequest)
		return
	}

	// 1.Verify ownership
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

	// 2.Get records from MongoDB (Clean User View)
	records, err := database.GetDNSRecords(h.MongoClient, domainID)
	if err != nil {
		http.Error(w, "Failed to fetch records: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

// DELETE /api/dns/records? domain_id=xxx&record_id=yyy
func (h *APIHandler) deleteRecord(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	recordID := r.URL.Query().Get("record_id")

	if domainID == "" || recordID == "" {
		http.Error(w, "domain_id and record_id are required", http.StatusBadRequest)
		return
	}

	// 1.Verify ownership
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

	// 2. Fetch the record details from MongoDB first (to know what to delete from SQL)
	record, err := database.GetDNSRecordByID(h.MongoClient, recordID)
	if err != nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	// 3. Determine the content stored in SQL
	// If it was proxied, SQL has the WAF IP. If not, it has the Origin IP.
	sqlContent := record.Content
	if record.Proxied && record.Type == "A" {
		wafIP := os.Getenv("WAF_PUBLIC_IP")
		if wafIP == "" {
			wafIP = "139.59.76.127"
		}
		sqlContent = wafIP
	}

	// 4. Delete from PowerDNS (MySQL)
	err = database.DeletePowerDNSRecordByContent(record.Name, record.Type, sqlContent)
	if err != nil {
		// Log error but continue to delete from Mongo to keep UI consistent?
		// Or fail. Let's fail so they can retry.
		http.Error(w, "Failed to delete from DNS backend: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 5. Delete from MongoDB
	err = database.DeleteDNSRecord(h.MongoClient, recordID)
	if err != nil {
		http.Error(w, "Failed to delete record: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Record deleted successfully",
	})
}