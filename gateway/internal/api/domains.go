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

// The pool of nameservers you created in PowerDNS
var realNameservers = []string{
	"jiniyas", "rabin", "niraj", "sabin", "rita", 
	"sneha", "exam", "bikalpa", "raju", "dhiren", "sanket",
}

type DoHResponse struct {
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

const nsSuffix = ".ns.minishield.tech"

// getRootDomain extracts the TLD+1 (e.g., "test.example.com" -> "example.com")
func getRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	// Takes the last two parts (e.g. lemepush.tech)
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

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

	// ---------------------------------------------------------
	// 1. STRICT SUBDOMAIN POLICY CHECK
	// ---------------------------------------------------------
	rootZone := getRootDomain(domain.Name)

	// If the user is trying to add a subdomain (e.g. test.lemepush.tech)
	// Check if the root (lemepush.tech) already exists in the system.
	if rootZone != domain.Name {
		existingRoot, err := database.GetDomainByName(h.MongoClient, rootZone)
		// If no error, it means we found the root domain!
		if err == nil && existingRoot != nil {
			w.WriteHeader(http.StatusConflict) // 409 Conflict
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "Root domain exists",
				"message": fmt.Sprintf("The root domain '%s' is already registered. Please add '%s' as an A Record under DNS Settings instead of creating a new Domain.", rootZone, domain.Name),
			})
			return
		}
	}
	// ---------------------------------------------------------

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
	domain.Proxied = false

	// 3. Save to MongoDB (Internal Routing & UI)
	createdDomain, err := database.CreateDomain(h.MongoClient, domain)
	if err != nil {
		// Handle duplicate key error (if they try to add exact same domain again)
		if strings.Contains(err.Error(), "duplicate key") {
			http.Error(w, "Domain already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create domain in DB", http.StatusInternalServerError)
		return
	}

	// 4. Provision PowerDNS (Zone + Fixed A Record)
	// Since we passed the strict check, we treat this as a NEW ZONE.
	
	// A. Create the Zone
	err = database.CreateDNSZone(domain.Name, domain.Nameservers)
	if err != nil {
		log.Printf("ERROR: Failed to create DNS Zone for %s: %v", domain.Name, err)
	} else {
		// B. Create the Fixed A Record (Public DNS -> WAF IP)
		// We use h.WafPublicIP which is loaded from ENV
		err = database.AddDNSRecord(domain.Name, "A", h.WafPublicIP, false, "")
		if err != nil {
			log.Printf("ERROR: Failed to create default A record for %s: %v", domain.Name, err)
		} else {
			log.Printf("SUCCESS: Provisioned DNS for %s -> %s", domain.Name, h.WafPublicIP)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createdDomain)
}

// lookupNSWithCloudflareDoH performs NS lookup using Cloudflare's DNS-over-HTTPS
func lookupNSWithCloudflareDoH(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=NS", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dohResp DoHResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, err
	}

	var nameservers []string
	for _, answer := range dohResp.Answer {
		if answer.Type == 2 { // NS record type
			ns := strings.TrimSuffix(answer.Data, ".")
			nameservers = append(nameservers, ns)
		}
	}

	return nameservers, nil
}

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

	// 3. Security: Ensure the user owns this domain
	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 4. Perform Live DNS Lookup using Cloudflare DoH
	nss, err := lookupNSWithCloudflareDoH(domain.Name)
	if err != nil {
		http.Error(w, "DNS Lookup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	verified := false

	// 5. Compare Found NS with Assigned NS
	for _, foundNS := range nss {
		cleanFound := strings.TrimSuffix(foundNS, ".")
		for _, assignedNS := range domain.Nameservers {
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
		err := database.UpdateDomainStatus(h.MongoClient, domain.ID, "active", true)
		if err != nil {
			http.Error(w, "DB Update failed", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "active",
			"message": "Domain successfully verified! WAF protection enabled.",
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