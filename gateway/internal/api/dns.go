package api

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/pkg/middleware"
	"web-app-firewall-ml-detection/pkg/response"
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

func (h *APIHandler) ManageRecords(w http.ResponseWriter, r *http.Request) {
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
		response.MethodNotAllowed(w)
	}
}

// POST /api/dns/records
func (h *APIHandler) addRecord(w http.ResponseWriter, r *http.Request) {
	var req DNSRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON")
		return
	}

	// 1. Sanitize Inputs (Trim Spaces)
	req.Name = strings.TrimSpace(req.Name)
	req.Content = strings.TrimSpace(req.Content)
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))

	// 2. Validate Required Fields
	if req.DomainID == "" || req.Type == "" || req.Content == "" {
		response.BadRequest(w, "domain_id, type, and content are required")
		return
	}

	// Rule 4.1: TTL Validation (60 - 86400)
	if req.TTL == 0 {
		req.TTL = 300 // Default
	}
	if req.TTL < 60 || req.TTL > 86400 {
		response.BadRequest(w, "TTL must be between 60 and 86400 seconds")
		return
	}

	// 3. STRICT CONTENT VALIDATION (Rule 2)
	switch req.Type {
	case "A":
		// Rule 2.1: MUST be valid IPv4, MUST NOT be IPv6 or hostname
		ip := net.ParseIP(req.Content)
		if ip == nil || ip.To4() == nil {
			response.BadRequest(w, "Content must be a valid IPv4 address")
			return
		}
	case "AAAA":
		// Rule 2.2: MUST be valid IPv6, MUST NOT be IPv4
		ip := net.ParseIP(req.Content)
		if ip == nil || ip.To4() != nil {
			response.BadRequest(w, "Content must be a valid IPv6 address")
			return
		}
	case "CNAME":
		// Rule 2.3: MUST be FQDN, MUST NOT be IP
		req.Content = strings.TrimSuffix(req.Content, ".") // Normalize

		if net.ParseIP(req.Content) != nil {
			response.BadRequest(w, "CNAME content must be a domain name, not an IP address")
			return
		}
		if !domainRegex.MatchString(req.Content) {
			response.BadRequest(w, "Invalid domain format in CNAME content")
			return
		}
	case "MX", "NS":
		req.Content = strings.TrimSuffix(req.Content, ".")
		if !domainRegex.MatchString(req.Content) {
			response.BadRequest(w, "Invalid domain format")
			return
		}
	case "TXT":
		if len(req.Content) > 2048 {
			response.BadRequest(w, "TXT record too long")
			return
		}
	default:
		// Optional: Block unknown types
		// response.BadRequest(w, "Unsupported record type")
		// return
	}

	// 4. Fetch the domain to verify ownership
	domain, err := database.GetDomainByID(h.MongoClient, req.DomainID)
	if err != nil {
		response.NotFound(w, "Domain not found")
		return
	}

	// 5. Security: Ensure the user owns this domain
	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}
	if domain.UserID != userID {
		response.Forbidden(w, "Unauthorized")
		return
	}

	if domain.Status != "active" {
		response.BadRequest(w, "Domain must be verified before adding records")
		return
	}

	// 7. Build the full record name (e.g., "www.example.com")
	recordName := domain.Name
	if req.Name != "" && req.Name != "@" {
		// Rule 4.2: Hostname Format Validation
		if !domainRegex.MatchString(req.Name) {
			response.BadRequest(w, "Record name contains invalid characters")
			return
		}
		recordName = req.Name + "." + domain.Name
	}

	// Rule 3: Root (@) Record Rules
	// The root hostname MUST NOT be a CNAME.
	if req.Type == "CNAME" && recordName == domain.Name {
		response.BadRequest(w, "Root domain (@) cannot be a CNAME record. Use A/AAAA instead.")
		return
	}

	// Rule 4.3: Target Domain Validation (CNAME)
	// No self-referencing CNAMEs
	if req.Type == "CNAME" {
		target := strings.TrimSuffix(req.Content, ".")
		if target == recordName {
			response.BadRequest(w, "CNAME cannot point to itself")
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
				response.InternalServerError(w, "Database error checking conflicts")
				return
			}
			if exists {
				// If checking CNAME against CNAME, it's a duplicate (Rule 1.1)
				// If checking CNAME against A, it's a coexistence error (Rule 1.2)
				response.Conflict(w, "CNAME record cannot coexist with other records (including other CNAMEs)")
				return
			}
		}
	} else {
		// Adding Non-CNAME (A, AAAA, MX, etc.)
		// Check if a CNAME already exists
		exists, err := database.CheckDNSRecordExists(h.MongoClient, req.DomainID, recordName, "CNAME")
		if err != nil {
			response.InternalServerError(w, "Database error checking conflicts")
			return
		}
		if exists {
			response.Conflict(w, "Cannot add record: A CNAME record already exists for this hostname")
			return
		}

		// Rule 1.1: Hostname Uniqueness within Record Type
		// "A hostname MUST NOT have more than one A record with the same value."
		// We allow multiple A records (Round Robin) as long as Content (IP) is different.
		// We use CheckDuplicateDNSRecord which checks (Name + Type + Content).
		exists, err = database.CheckDuplicateDNSRecord(h.MongoClient, req.DomainID, recordName, req.Type, req.Content)
		if err != nil {
			response.InternalServerError(w, "Database error checking duplicates")
			return
		}
		if exists {
			response.Conflict(w, "Duplicate record already exists")
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
		response.InternalServerError(w, "Database Error: "+err.Error())
		return
	}
	newRecord.ID = recordID

	// 12. Add to PowerDNS (Resolution Backend)
	err = database.AddPowerDNSRecord(recordName, req.Type, req.Content, req.Proxied, wafIP)
	if err != nil {
		// Log error but keep mongo record so user can try deleting/re-adding
		response.InternalServerError(w, "DNS Propagation Error: "+err.Error())
		return
	}

	response.Success(w, map[string]interface{}{
		"record": newRecord,
	}, "DNS record added successfully")
}

// PUT /api/dns/records?domain_id=xxx&record_id=yyy
// [RENAMED & UPDATED] Handles both Proxy Toggle and Origin SSL Toggle
func (h *APIHandler) updateRecord(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	recordID := r.URL.Query().Get("record_id")

	if domainID == "" || recordID == "" {
		response.BadRequest(w, "domain_id and record_id are required")
		return
	}

	// 1. Parse a Generic Request Payload
	// We capture all possible fields.
	var req struct {
		Action    string `json:"action"`     // "toggle_origin_ssl" or empty (default to proxy)
		Proxied   bool   `json:"proxied"`    // For Proxy updates
		OriginSSL bool   `json:"origin_ssl"` // For SSL updates
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON")
		return
	}

	// 2. Security: Verify Ownership (Common for all updates)
	domain, err := database.GetDomainByID(h.MongoClient, domainID)
	if err != nil {
		response.NotFound(w, "Domain not found")
		return
	}
	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}
	if domain.UserID != userID {
		response.Forbidden(w, "Unauthorized")
		return
	}

	// ---------------------------------------------------------
	// BRANCH 1: Origin SSL Update
	// ---------------------------------------------------------
	if req.Action == "toggle_origin_ssl" {
		// Call the DB function to update just the SSL flag
		err := database.UpdateDNSRecordOriginSSL(h.MongoClient, recordID, req.OriginSSL)
		if err != nil {
			response.InternalServerError(w, "Failed to update Origin SSL: "+err.Error())
			return
		}

		response.Success(w, map[string]interface{}{
			"origin_ssl": req.OriginSSL,
		}, "Origin SSL status updated")
		return
	}

	// ---------------------------------------------------------
	// BRANCH 2: Proxy Status Update (Default / Legacy)
	// ---------------------------------------------------------
	// If action is empty or "toggle_proxy", we run the complex proxy logic.

	// A. Get the OLD record state
	oldRecord, err := database.GetDNSRecordByID(h.MongoClient, recordID)
	if err != nil {
		response.NotFound(w, "Record not found")
		return
	}

	// B. Calculate what needs to be removed from PowerDNS
	wafIP := os.Getenv("WAF_PUBLIC_IP")
	if wafIP == "" {
		wafIP = "139.59.76.127"
	}

	contentToDelete := oldRecord.Content
	typeToDelete := oldRecord.Type

	shouldHaveBeenProxied := oldRecord.Proxied
	// Safety check: TXT/MX/NS/SOA never proxy
	if oldRecord.Type == "TXT" || oldRecord.Type == "MX" || oldRecord.Type == "NS" || oldRecord.Type == "SOA" {
		shouldHaveBeenProxied = false
	}

	if shouldHaveBeenProxied {
		contentToDelete = wafIP
		typeToDelete = "A"
	}

	// C. Delete OLD entry from PowerDNS
	err = database.DeletePowerDNSRecordByContent(oldRecord.Name, typeToDelete, contentToDelete)
	if err != nil {
		response.InternalServerError(w, "Failed to update DNS (Delete Phase): "+err.Error())
		return
	}

	// D. Update MongoDB to NEW state
	err = database.UpdateDNSRecordProxy(h.MongoClient, recordID, req.Proxied)
	if err != nil {
		response.InternalServerError(w, "Failed to update database")
		return
	}

	// E. Add NEW entry to PowerDNS
	err = database.AddPowerDNSRecord(oldRecord.Name, oldRecord.Type, oldRecord.Content, req.Proxied, wafIP)
	if err != nil {
		response.InternalServerError(w, "Failed to update DNS (Add Phase): "+err.Error())
		return
	}

	response.Success(w, map[string]interface{}{
		"proxied": req.Proxied,
	}, "Proxy status updated")
}
// GET /api/dns/records? domain_id=xxx
func (h *APIHandler) listRecords(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	if domainID == "" {
		response.BadRequest(w, "domain_id is required")
		return
	}

	// 1.Verify ownership
	domain, err := database.GetDomainByID(h.MongoClient, domainID)
	if err != nil {
		response.NotFound(w, "Domain not found")
		return
	}

	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}
	if domain.UserID != userID {
		response.Forbidden(w, "Unauthorized")
		return
	}

	// 2.Get records from MongoDB (Clean User View)
	records, err := database.GetDNSRecords(h.MongoClient, domainID)
	if err != nil {
		response.InternalServerError(w, "Failed to fetch records: "+err.Error())
		return
	}

	response.JSON(w, records, http.StatusOK)
}

// DELETE /api/dns/records? domain_id=xxx&record_id=yyy
func (h *APIHandler) deleteRecord(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	recordID := r.URL.Query().Get("record_id")

	if domainID == "" || recordID == "" {
		response.BadRequest(w, "domain_id and record_id are required")
		return
	}

	// 1.Verify ownership
	domain, err := database.GetDomainByID(h.MongoClient, domainID)
	if err != nil {
		response.NotFound(w, "Domain not found")
		return
	}

	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}
	if domain.UserID != userID {
		response.Forbidden(w, "Unauthorized")
		return
	}

	// 2. Fetch the record details from MongoDB first
	record, err := database.GetDNSRecordByID(h.MongoClient, recordID)
	if err != nil {
		response.NotFound(w, "Record not found")
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
		response.InternalServerError(w, "Failed to delete from DNS backend: "+err.Error())
		return
	}

	// 5. Delete from MongoDB
	err = database.DeleteDNSRecord(h.MongoClient, recordID)
	if err != nil {
		response.InternalServerError(w, "Failed to delete record: "+err.Error())
		return
	}

	response.Success(w, nil, "Record deleted successfully")
}
