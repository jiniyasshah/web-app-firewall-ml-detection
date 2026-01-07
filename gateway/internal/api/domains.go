package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
)

var realNameservers = []string{
	"jiniyas", "rabin", "niraj", "sabin", "rita", 
	"sneha", "exam", "bikalpa", "raju", "dhiren", "sanket",
}

const nsSuffix = ".ns.minishield.tech"

// RDAP Response Structure (The Official Registrar Data)
type RDAPResponse struct {
	Nameservers []struct {
		LdhName string `json:"ldhName"` // This holds "ns1.example.com"
	} `json:"nameservers"`
}

func getRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func (h *APIHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	var domain detector.Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		h.WriteJSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 1. STRICT SUBDOMAIN POLICY CHECK
	rootZone := getRootDomain(domain.Name)
	if rootZone != domain.Name {
		existingRoot, err := database.GetDomainByName(h.MongoClient, rootZone)
		if err == nil && existingRoot != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "Root domain exists",
				"message": fmt.Sprintf("The root domain '%s' is already registered. Please add '%s' as an A Record.", rootZone, domain.Name),
			})
			return
		}
	}

	// 2. Assign 2 Random Real Nameservers
	rand.Seed(time.Now().UnixNano())
	idx1 := rand.Intn(len(realNameservers))
	idx2 := rand.Intn(len(realNameservers))
	for idx1 == idx2 {
		idx2 = rand.Intn(len(realNameservers))
	}

	ns1 := realNameservers[idx1] + nsSuffix
	ns2 := realNameservers[idx2] + nsSuffix

	domain.UserID = userID
	domain.Nameservers = []string{ns1, ns2}
	domain.Status = "pending_verification"

	// 3. Save to MongoDB
	createdDomain, err := database.CreateDomain(h.MongoClient, domain)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			h.WriteJSONError(w, "Domain already exists", http.StatusConflict)
			return
		}
		h.WriteJSONError(w, "Failed to create domain in DB", http.StatusInternalServerError)
		return
	}

	// 4. Provision PowerDNS Zone (SOA and NS only)
	err = database.CreateDNSZone(domain.Name, domain.Nameservers)
	if err != nil {
		log.Printf("ERROR: Failed to create DNS Zone: %v", err)
	}

	// NOTE: We do NOT create a default A record here. The zone is created empty.
	// The user must verify the domain and then explicitly add records.

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createdDomain)
}

// checkRegistrarRDAP queries the Official Registry (RDAP) to find the configured Nameservers.
func checkRegistrarRDAP(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// rdap.org is a redirector that finds the correct registry (like Verisign, Radix, etc.)
	url := fmt.Sprintf("https://rdap.org/domain/%s", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("domain not registered found")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rdapResp RDAPResponse
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return nil, err
	}

	var nameservers []string
	for _, ns := range rdapResp.Nameservers {
		cleanName := strings.TrimSuffix(ns.LdhName, ".")
		nameservers = append(nameservers, cleanName)
	}

	return nameservers, nil
}

func (h *APIHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domainID := r.URL.Query().Get("id")
	if domainID == "" {
		h.WriteJSONError(w, "Missing domain id", http.StatusBadRequest)
		return
	}

	domain, err := database.GetDomainByID(h.MongoClient, domainID)
	if err != nil {
		h.WriteJSONError(w, "Domain not found", http.StatusNotFound)
		return
	}

	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		h.WriteJSONError(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 4. SECURITY CHECK: Use RDAP to check the Registrar directly.
	foundNS, err := checkRegistrarRDAP(domain.Name)
	if err != nil {
		log.Printf("RDAP Lookup failed: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Verification Unavailable", 
			"details": err.Error(),
		})
		return
	}

	// 5. STRICT VERIFICATION
	matchedCount := 0
	
	for _, assignedNS := range domain.Nameservers {
		found := false
		for _, liveNS := range foundNS {
			if strings.EqualFold(liveNS, assignedNS) {
				found = true
				break
			}
		}
		if found {
			matchedCount++
		}
	}

	verified := (matchedCount == len(domain.Nameservers)) && (len(domain.Nameservers) > 0)

	w.Header().Set("Content-Type", "application/json")

if verified {
		// 1. CRITICAL: Revoke old ownership
		// If another user had this domain (Active or Pending), remove their record
		// so this new User becomes the sole Owner.
		err := database.RevokeOldOwnership(h.MongoClient, domain.Name, domain.ID)
		if err != nil {
			log.Printf("Error revoking old ownership for %s: %v", domain.Name, err)
			// We continue; failing to delete shouldn't block the valid user, 
			// but we should log it.
		}

		// 2. Activate the new domain
		err = database.UpdateDomainStatus(h.MongoClient, domain.ID, "active")
		if err != nil {
			h.WriteJSONError(w, "DB Update failed", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "active",
			"message": "Domain successfully verified! You are now the owner.",
		})
	} else {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "pending_verification",
			"message":            "Verification failed. Your Registrar nameservers do not match the assigned ones.",
			"assigned_ns":        domain.Nameservers,
			"found_at_registrar": foundNS,
		})
	}
}

func (h *APIHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domains, err := database.GetDomainsByUser(h.MongoClient, userID)
	if err != nil {
		h.WriteJSONError(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(domains)
}