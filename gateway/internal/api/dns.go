package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

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

// ManageRecords handles GET, POST, PUT, DELETE for DNS records
func (h *APIHandler) ManageRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listRecords(w, r)
	case http.MethodPost:
		h.addRecord(w, r)
	case http.MethodPut:
		h.toggleProxy(w, r)
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

	// [NEW] Sanitize Content: Remove trailing dots for CNAME, MX, NS
	if req.Type == "CNAME" || req.Type == "MX" || req.Type == "NS" {
		req.Content = strings.TrimSuffix(req.Content, ".")
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

	// 8.Add to MongoDB (Source of Truth for User Display & Proxy Routing)
	newRecord := database.DNSRecord{
		DomainID: req.DomainID,
		Name:     recordName,
		Type:     req.Type,
		Content:  req.Content, // Store the ORIGIN IP / CNAME Target
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
	// If proxied=true, this will automatically insert an A record pointing to wafIP
	err = database.AddPowerDNSRecord(recordName, req.Type, req.Content, req.Proxied, wafIP)
	if err != nil {
		// Log error but generally keep the mongo record so user can try deleting/re-adding
		http.Error(w, "DNS Propagation Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "DNS record added successfully",
		"record":  newRecord,
	})
}

// PUT /api/dns/records?domain_id=xxx&record_id=yyy
// Body: { "proxied": true/false }
func (h *APIHandler) toggleProxy(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	recordID := r.URL.Query().Get("record_id")

	if domainID == "" || recordID == "" {
		http.Error(w, "domain_id and record_id are required", http.StatusBadRequest)
		return
	}

	// 1. Parse the new state
	var req struct {
		Proxied bool `json:"proxied"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 2. Security Checks
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

	// 3. Get the OLD record state (to know what to delete from SQL)
	oldRecord, err := database.GetDNSRecordByID(h.MongoClient, recordID)
	if err != nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	// 4. Calculate what the SQL database currently holds (Old State)
	// We need to delete this specific entry to avoid duplicates or conflicts
	wafIP := os.Getenv("WAF_PUBLIC_IP")
	if wafIP == "" {
		wafIP = "139.59.76.127"
	}

	contentToDelete := oldRecord.Content
	typeToDelete := oldRecord.Type

	// logic: if it *was* proxied, SQL has the WAF IP and Type A
	shouldHaveBeenProxied := oldRecord.Proxied
	// Safety check: TXT/MX/NS/SOA never proxy
	if oldRecord.Type == "TXT" || oldRecord.Type == "MX" || oldRecord.Type == "NS" || oldRecord.Type == "SOA" {
		shouldHaveBeenProxied = false
	}

	if shouldHaveBeenProxied {
		contentToDelete = wafIP
		typeToDelete = "A"
	}

	// 5. Delete OLD entry from PowerDNS
	err = database.DeletePowerDNSRecordByContent(oldRecord.Name, typeToDelete, contentToDelete)
	if err != nil {
		http.Error(w, "Failed to update DNS (Delete Phase): "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 6. Update MongoDB to NEW state
	err = database.UpdateDNSRecordProxy(h.MongoClient, recordID, req.Proxied)
	if err != nil {
		http.Error(w, "Failed to update database", http.StatusInternalServerError)
		return
	}

	// 7. Add NEW entry to PowerDNS
	// The Add function handles the logic: if req.Proxied is true, it inserts WAF IP. If false, Real IP.
	// It also respects the internal check for TXT/MX/NS/SOA (wont proxy them even if req.Proxied is true)
	err = database.AddPowerDNSRecord(oldRecord.Name, oldRecord.Type, oldRecord.Content, req.Proxied, wafIP)
	if err != nil {
		http.Error(w, "Failed to update DNS (Add Phase): "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Proxy status updated",
		"proxied": req.Proxied,
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

	// 2. Fetch the record details from MongoDB first
	record, err := database.GetDNSRecordByID(h.MongoClient, recordID)
	if err != nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	// 3. Determine the content stored in SQL to delete it correctly
	// If proxied, the SQL backend holds an A record with WAF IP.
	sqlType := record.Type
	sqlContent := record.Content

	// Safety check again for verification records
	isProxiable := true
	if record.Type == "TXT" || record.Type == "MX" || record.Type == "NS" || record.Type == "SOA" {
		isProxiable = false
	}

	if record.Proxied && isProxiable {
		sqlType = "A"
		wafIP := os.Getenv("WAF_PUBLIC_IP")
		if wafIP == "" {
			wafIP = "139.59.76.127"
		}
		sqlContent = wafIP
	}

	// 4. Delete from PowerDNS (MySQL)
	err = database.DeletePowerDNSRecordByContent(record.Name, sqlType, sqlContent)
	if err != nil {
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