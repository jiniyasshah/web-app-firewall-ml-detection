package api

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"web-app-firewall-ml-detection/internal/database"
)

// Regex for validating domain names (alphanumeric, hyphens, dots)
// This prevents characters like spaces, double dots "..", or injection attempts
var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

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

	// 1. Sanitize Inputs (Trim Spaces)
	req.Name = strings.TrimSpace(req.Name)
	req.Content = strings.TrimSpace(req.Content)
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))

	// 2. Validate Required Fields
	if req.DomainID == "" || req.Type == "" || req.Content == "" {
		http.Error(w, "domain_id, type, and content are required", http.StatusBadRequest)
		return
	}

	// 3. STRICT CONTENT VALIDATION
	switch req.Type {
	case "A":
		// Must be a valid IP address
		if net.ParseIP(req.Content) == nil {
			http.Error(w, "Invalid IP address content for A record", http.StatusBadRequest)
			return
		}
	case "CNAME", "MX", "NS":
		// Remove trailing dot if present (normalization)
		req.Content = strings.TrimSuffix(req.Content, ".")

		// Check for common typos explicitly
		if strings.Contains(req.Content, "..") {
			http.Error(w, "Content contains invalid sequence '..'", http.StatusBadRequest)
			return
		}
		if strings.Contains(req.Content, " ") {
			http.Error(w, "Content must not contain spaces", http.StatusBadRequest)
			return
		}
		// Validate against domain regex
		if !domainRegex.MatchString(req.Content) {
			http.Error(w, "Invalid domain format in content", http.StatusBadRequest)
			return
		}
	case "TXT":
		// TXT records are generally free-form, but check for extreme length if needed
		if len(req.Content) > 1024 {
			http.Error(w, "TXT record too long", http.StatusBadRequest)
			return
		}
	default:
		// Optional: Reject unknown types
		// http.Error(w, "Unsupported record type", http.StatusBadRequest)
		// return
	}

	// 4. Fetch the domain to verify ownership
	domain, err := database.GetDomainByID(h.MongoClient, req.DomainID)
	if err != nil {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// 5. Security: Ensure the user owns this domain
	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 6. Check domain is verified
	if domain.Status != "active" {
		http.Error(w, "Domain must be verified before adding records", http.StatusBadRequest)
		return
	}

	// 7. Build the full record name
	recordName := domain.Name
	if req.Name != "" && req.Name != "@" {
		// Validate the Subdomain Name part as well
		if strings.Contains(req.Name, "..") || strings.Contains(req.Name, " ") {
			http.Error(w, "Record name contains invalid characters", http.StatusBadRequest)
			return
		}
		recordName = req.Name + "." + domain.Name
	}

	// 8. Get WAF Public IP
	wafIP := os.Getenv("WAF_PUBLIC_IP")
	if wafIP == "" {
		wafIP = "139.59.76.127"
	}

	// 9. Default TTL
	if req.TTL == 0 {
		req.TTL = 300
	}

	// 10. Check for Duplicates (NEW)
	exists, err := database.CheckDuplicateDNSRecord(h.MongoClient, req.DomainID, recordName, req.Type, req.Content)
	if err != nil {
		http.Error(w, "Database error checking duplicates", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Duplicate record already exists", http.StatusConflict)
		return
	}

	// 11. Add to MongoDB (Source of Truth for User Display & Proxy Routing)
	newRecord := database.DNSRecord{
		DomainID: req.DomainID,
		Name:     recordName,
		Type:     req.Type,
		Content:  req.Content, // Store the CLEANED content
		TTL:      req.TTL,
		Proxied:  req.Proxied,
	}

	recordID, err := database.CreateDNSRecord(h.MongoClient, newRecord)
	if err != nil {
		http.Error(w, "Database Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	newRecord.ID = recordID

	// 12. Add to PowerDNS (Resolution Backend)
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