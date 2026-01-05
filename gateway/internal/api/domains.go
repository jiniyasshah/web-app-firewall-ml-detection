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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	var domain detector.Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
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
	domain.Proxied = false

	// 3. Save to MongoDB
	createdDomain, err := database.CreateDomain(h.MongoClient, domain)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			http.Error(w, "Domain already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create domain in DB", http.StatusInternalServerError)
		return
	}

	// 4. Provision PowerDNS and Default Records
	err = database.CreateDNSZone(domain.Name, domain.Nameservers)
	if err != nil {
		log.Printf("ERROR: Failed to create DNS Zone: %v", err)
	} else {
		// Create the root A record pointing to WAF (Default setup)
		// We add it to MongoDB (Display) AND PowerDNS (Resolution)
		
		// Mongo
		mongoRecord := database.DNSRecord{
			DomainID: createdDomain.ID, // We need the ID from CreateDomain? createdDomain has it.
			Name:     domain.Name,
			Type:     "A",
			Content:  h.WafPublicIP, // Initial setup points to WAF usually, or we leave empty? 
			                       // Code below used WafPublicIP. 
			TTL:      300,
			Proxied:  false,
		}
		// If CreateDomain didn't return ID (it does in struct), we are good.
		// NOTE: createdDomain.ID might be empty if CreateDomain didn't populate it on the return struct?
		// Looking at mongo.go: "if domain.ID == "" ... InsertOne". The returned struct in `mongo.go` is the same passed in.
		// So we must ensure `createdDomain` has the ID.
		// Actually CreateDomain in `mongo.go` sets the ID if empty. It returns the modified domain.
		
		_, _ = database.CreateDNSRecord(h.MongoClient, mongoRecord)

		// SQL
		err = database.AddPowerDNSRecord(domain.Name, "A", h.WafPublicIP, false, "")
		if err != nil {
			log.Printf("ERROR: Failed to create A record: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createdDomain)
}

// checkRegistrarRDAP queries the Official Registry (RDAP) to find the configured Nameservers.
// This is immune to "Child Lying" because we talk to the Registry, not the DNS server.
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
		// RDAP returns clean names "ns1.example.com", usually without trailing dot.
		// We trim just in case.
		cleanName := strings.TrimSuffix(ns.LdhName, ".")
		nameservers = append(nameservers, cleanName)
	}

	return nameservers, nil
}

func (h *APIHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domainID := r.URL.Query().Get("id")
	if domainID == "" {
		http.Error(w, "Missing domain id", http.StatusBadRequest)
		return
	}

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

	// 4. SECURITY CHECK: Use RDAP to check the Registrar directly.
	foundNS, err := checkRegistrarRDAP(domain.Name)
	if err != nil {
		log.Printf("RDAP Lookup failed: %v", err)
		// We return the error so the user knows something went wrong
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Verification Unavailable", 
			"details": err.Error(),
		})
		return
	}

	// 5. STRICT VERIFICATION: Ensure ALL assigned NS are present at Registrar
	matchedCount := 0
	
	for _, assignedNS := range domain.Nameservers {
		found := false
		for _, liveNS := range foundNS {
			// Case-insensitive comparison
			if strings.EqualFold(liveNS, assignedNS) {
				found = true
				break
			}
		}
		if found {
			matchedCount++
		}
	}

	// Pass if we found ALL assigned nameservers in the RDAP response
	verified := (matchedCount == len(domain.Nameservers)) && (len(domain.Nameservers) > 0)

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
			"status":             "pending_verification",
			"message":            "Verification failed. Your Registrar nameservers do not match the assigned ones.",
			"assigned_ns":        domain.Nameservers,
			"found_at_registrar": foundNS, // This will now show the REAL list (e.g., ["niraj", "dhiren"])
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