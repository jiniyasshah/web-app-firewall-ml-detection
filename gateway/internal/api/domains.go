package api

import (
	"encoding/json"
	"log"
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

	userID := r. Context().Value("user_id").(string)

	var domain detector.Domain
	if err := json. NewDecoder(r.Body).Decode(&domain); err != nil {
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
	domain. Status = "pending_verification" // Start as pending
	domain. Proxied = false                 // Disabled until verified

	// CreateDomain now returns the domain with ID and CreatedAt populated
	createdDomain, err := database.CreateDomain(h.MongoClient, domain)
	if err != nil {
		http.Error(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createdDomain)
}

// VerifyDomain checks if the user actually updated their NS records
// Usage: POST /api/domains/verify? id=6956726f0553824e125d7cb8
// VerifyDomain checks if the user actually updated their NS records
func (h *APIHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Get domain ID from query parameter
	domainID := r.URL.Query().Get("id")
	if domainID == "" {
		http.Error(w, "Missing domain id", http.StatusBadRequest)
		return
	}

	// 2. Fetch Domain from DB to get assigned NS
	domain, err := database.GetDomainByID(h.MongoClient, domainID)
	if err != nil {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	// 3. Security:  Ensure the user owns this domain
	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 4. Perform Live DNS Lookup
	nss, err := net.LookupNS(domain.Name)
	if err != nil {
		http.Error(w, "DNS Lookup failed:  "+err.Error(), http.StatusInternalServerError)
		return
	}

	verified := false

	// 5. Compare Found NS with Assigned NS
	for _, foundNS := range nss {
		cleanFound := strings.TrimSuffix(foundNS. Host, ".")
		for _, assignedNS := range domain. Nameservers {
			if strings.EqualFold(cleanFound, assignedNS) {
				verified = true
				break
			}
		}
		if verified {
			break
		}
	}

	// 6. Update Status & Respond
	w.Header().Set("Content-Type", "application/json")

	if verified {
		// Update domain status in MongoDB
		err := database.UpdateDomainStatus(h. MongoClient, domain.ID, "active", true)
		if err != nil {
			http.Error(w, "DB Update failed", http.StatusInternalServerError)
			return
		}

		// Create the zone in PowerDNS so user can add records
		err = database.CreateDNSZone(domain. Name, domain. Nameservers)
		if err != nil {
			// Log but don't fail - zone might already exist
			log.Printf("Warning: Failed to create DNS zone:  %v", err)
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":   "active",
			"message": "Domain successfully verified!  WAF protection enabled.",
		})
	} else {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "pending_verification",
			"message":       "Verification failed. We did not find the correct Nameservers.",
			"found_records": nss,
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