// type: uploaded file
// fileName: jiniyasshah/web-app-firewall-ml-detection/web-app-firewall-ml-detection-test/gateway/internal/api/dns.go
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
// Enforces: Start/End alphanumeric, max 63 chars per label, no spaces.
var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

type DNSRecordRequest struct {
	DomainID string `json:"domain_id"`
	Name     string `json:"name"`    // "@" for root, "www", "api", etc.
	Type     string `json:"type"`    // "A", "AAAA", "CNAME", "MX", "TXT"
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

	// Rule 4.1: TTL Validation (60 - 86400)
	if req.TTL == 0 {
		req.TTL = 300 // Default
	}
	if req.TTL < 60 || req.TTL > 86400 {
		http.Error(w, "TTL must be between 60 and 86400 seconds", http.StatusBadRequest)
		return
	}

	// 3. STRICT CONTENT VALIDATION (Rule 2)
	switch req.Type {
	case "A":
		// Rule 2.1: MUST be valid IPv4, MUST NOT be IPv6 or hostname
		ip := net.ParseIP(req.Content)
		if ip == nil || ip.To4() == nil {
			http.Error(w, "Content must be a valid IPv4 address", http.StatusBadRequest)
			return
		}
	case "AAAA":
		// Rule 2.2: MUST be valid IPv6, MUST NOT be IPv4
		ip := net.ParseIP(req.Content)
		if ip == nil || ip.To4() != nil {
			http.Error(w, "Content must be a valid IPv6 address", http.StatusBadRequest)
			return
		}
	case "CNAME":
		// Rule 2.3: MUST be FQDN, MUST NOT be IP
		req.Content = strings.TrimSuffix(req.Content, ".") // Normalize

		if net.ParseIP(req.Content) != nil {
			http.Error(w, "CNAME content must be a domain name, not an IP address", http.StatusBadRequest)
			return
		}
		if !domainRegex.MatchString(req.Content) {
			http.Error(w, "Invalid domain format in CNAME content", http.StatusBadRequest)
			return
		}
	case "MX", "NS":
		req.Content = strings.TrimSuffix(req.Content, ".")
		if !domainRegex.MatchString(req.Content) {
			http.Error(w, "Invalid domain format", http.StatusBadRequest)
			return
		}
	case "TXT":
		if len(req.Content) > 2048 {
			http.Error(w, "TXT record too long", http.StatusBadRequest)
			return
		}
	default:
		// Optional: Block unknown types
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

	if domain.Status != "active" {
		http.Error(w, "Domain must be verified before adding records", http.StatusBadRequest)
		return
	}

	// 7. Build the full record name (e.g., "www.example.com")
	recordName := domain.Name
	if req.Name != "" && req.Name != "@" {
		// Rule 4.2: Hostname Format Validation
		if !domainRegex.MatchString(req.Name) {
			http.Error(w, "Record name contains invalid characters", http.StatusBadRequest)
			return
		}
		recordName = req.Name + "." + domain.Name
	}

	// Rule 3: Root (@) Record Rules
	// The root hostname MUST NOT be a CNAME.
	if req.Type == "CNAME" && recordName == domain.Name {
		http.Error(w, "Root domain (@) cannot be a CNAME record. Use A/AAAA instead.", http.StatusBadRequest)
		return
	}

	// Rule 4.3: Target Domain Validation (CNAME)
	// No self-referencing CNAMEs
	if req.Type == "CNAME" {
		target := strings.TrimSuffix(req.Content, ".")
		if target == recordName {
			http.Error(w, "CNAME cannot point to itself", http.StatusBadRequest)
			return
		}
	}

	// 8. Get WAF Public IP (for proxying)
	wafIP := os.Getenv("WAF_PUBLIC_IP")
	if wafIP == "" {
		wafIP = "139.59.76.127"
	}

	// 10. Check for Conflicts & Duplicates (Rules 1.1 & 1.2)

	// List of types to check against for exclusivity
	conflictTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}

	// Rule 1.2: CNAME Exclusivity
	// A hostname that has a CNAME record MUST NOT have any other record type.
	// A hostname that has other records MUST NOT have a CNAME.

	if req.Type == "CNAME" {
		// Check if *any* record exists for this name (including existing CNAMEs)
		for _, t := range conflictTypes {
			exists, err := database.CheckDNSRecordExists(h.MongoClient, req.DomainID, recordName, t)
			if err != nil {
				http.Error(w, "Database error checking conflicts", http.StatusInternalServerError)
				return
			}
			if exists {
				// If checking CNAME against CNAME, it's a duplicate (Rule 1.1)
				// If checking CNAME against A, it's a coexistence error (Rule 1.2)
				http.Error(w, "CNAME record cannot coexist with other records (including other CNAMEs)", http.StatusConflict)
				return
			}
		}
	} else {
		// Adding Non-CNAME (A, AAAA, MX, etc.)
		// Check if a CNAME already exists
		exists, err := database.CheckDNSRecordExists(h.MongoClient, req.DomainID, recordName, "CNAME")
		if err != nil {
			http.Error(w, "Database error checking conflicts", http.StatusInternalServerError)
			return
		}
		if exists {
			http.Error(w, "Cannot add record: A CNAME record already exists for this hostname", http.StatusConflict)
			return
		}

		// Rule 1.1: Hostname Uniqueness within Record Type
		// "A hostname MUST NOT have more than one A record with the same value."
		// We allow multiple A records (Round Robin) as long as Content (IP) is different.
		// We use CheckDuplicateDNSRecord which checks (Name + Type + Content).
		exists, err = database.CheckDuplicateDNSRecord(h.MongoClient, req.DomainID, recordName, req.Type, req.Content)
		if err != nil {
			http.Error(w, "Database error checking duplicates", http.StatusInternalServerError)
			return
		}
		if exists {
			http.Error(w, "Duplicate record already exists", http.StatusConflict)
			return
		}
	}

	// 11. Add to MongoDB (Source of Truth)
	newRecord := database.DNSRecord{
		DomainID: req.DomainID,
		Name:     recordName,
		Type:     req.Type,
		Content:  req.Content,
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
		// Log error but keep mongo record so user can try deleting/re-adding
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

	// 3. Get the OLD record state
	oldRecord, err := database.GetDNSRecordByID(h.MongoClient, recordID)
	if err != nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	// 4. Calculate what the SQL database currently holds (Old State)
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
	// The Add function handles the logic: if req.Proxied is true, it inserts WAF IP.
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