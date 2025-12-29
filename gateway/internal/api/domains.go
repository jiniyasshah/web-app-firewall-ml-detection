package api

import (
	"encoding/json"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
)

// The pool of nameservers you created in PowerDNS
var realNameservers = []string{
	"jiniyas", "rabin", "niraj", "sabin", "rita", 
	"sneha", "exam", "bikalpa", "raju", "dhiren", "sanket",
}

const nsSuffix = ".ns.minishield.tech"

func (h *APIHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	var domain detector.Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 1. Assign 2 Random Real Nameservers
	// In production, you might want to cycle these round-robin
	rand.Seed(time.Now().UnixNano())
	idx1 := rand.Intn(len(realNameservers))
	idx2 := rand.Intn(len(realNameservers))
	for idx1 == idx2 { // Ensure they are different
		idx2 = rand.Intn(len(realNameservers))
	}

	ns1 := realNameservers[idx1] + nsSuffix
	ns2 := realNameservers[idx2] + nsSuffix

	domain.UserID = userID
	domain.Nameservers = []string{ns1, ns2}
	domain.Status = "pending_verification" // Start as pending
	domain.Proxied = false                 // Disabled until verified

	if err := database.CreateDomain(h.MongoClient, domain); err != nil {
		http.Error(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(domain)
}

// [NEW] VerifyDomain checks if the user actually updated their NS records
func (h *APIHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	// 1. Parse Request
	var req struct {
		DomainID string `json:"domain_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", 400); return
	}

	// 2. Fetch Domain from DB to get assigned NS
	domain, err := database.GetDomainByID(h.MongoClient, req.DomainID)
	if err != nil {
		http.Error(w, "Domain not found", 404); return
	}

	// Security: Ensure the user owns this domain
	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		http.Error(w, "Unauthorized", 403); return
	}

	// 3. Perform Live DNS Lookup (The "Check")
	// We ask the global internet: "What are the NS records for this domain?"
	nss, err := net.LookupNS(domain.Name)
	if err != nil {
		http.Error(w, "DNS Lookup failed: "+err.Error(), 500); return
	}

	verified := false
	
	// 4. Compare Found NS with Assigned NS
	// We look for at least one match
	for _, foundNS := range nss {
		// Clean up string (DNS often returns trailing dot, e.g., "ns1.com.")
		cleanFound := strings.TrimSuffix(foundNS.Host, ".")
		
		for _, assignedNS := range domain.Nameservers {
			if strings.EqualFold(cleanFound, assignedNS) {
				verified = true
				break
			}
		}
		if verified { break }
	}

	// 5. Update Status
	if verified {
		err := database.UpdateDomainStatus(h.MongoClient, domain.ID, "active", true)
		if err != nil {
			http.Error(w, "DB Update failed", 500); return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status": "active", 
			"message": "Domain successfully verified! WAF protection enabled.",
		})
	} else {
		// Just return failure, don't update DB
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "pending_verification",
			"message": "Verification failed. We did not find the correct Nameservers.",
			"found_records": nss, // Debug info for user
		})
	}
}

func (h *APIHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domains, err := database.GetDomainsByUser(h.MongoClient, userID)
	if err != nil {
		http.Error(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(domains)
}