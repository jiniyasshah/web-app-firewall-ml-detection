package api

import (
	"encoding/json"
	"math/rand"
	"net/http"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
)

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

	// Generate 2 Random Nameservers
	ns1 := nsNames[rand.Intn(len(nsNames))] + ".ns.example.local"
	ns2 := nsNames[rand.Intn(len(nsNames))] + ".ns.example.local"

	domain.UserID = userID
	domain.Nameservers = []string{ns1, ns2}
	domain.Status = "unverified"

	if err := database.CreateDomain(h.MongoClient, domain); err != nil {
		http.Error(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(domain)
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