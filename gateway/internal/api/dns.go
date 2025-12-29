package api

import (
	"encoding/json"
	"net/http"
	"os"
	"web-app-firewall-ml-detection/internal/database"
)

type DNSRecordRequest struct {
	Domain  string `json:"domain"`
	Type    string `json:"type"`     // "A", "CNAME", etc.
	Content string `json:"content"`  // "1.2.3.4"
	Proxied bool   `json:"proxied"`  // TRUE = Protected by WAF, FALSE = Bypass
}

func (h *APIHandler) AddRecord(w http.ResponseWriter, r *http.Request) {
	var req DNSRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	// 1. Get WAF Public IP (From Env or Hardcoded)
	wafIP := os.Getenv("WAF_PUBLIC_IP")
	if wafIP == "" {
		wafIP = "139.59.76.127"
	}

	// 2. Update Public DNS (MySQL)
	err := database.AddDNSRecord(req.Domain, req.Type, req.Content, req.Proxied, wafIP)
	if err != nil {
		http.Error(w, "Database Error: "+err.Error(), 500)
		return
	}

	// 3. Update Internal Routing (MongoDB) ONLY if it's an A record
	if req.Type == "A" {
		// FIX: Use h.MongoClient instead of h.client
		err = database.UpdateDomainRouting(h.MongoClient, req.Domain, req.Content, req.Proxied)
		if err != nil {
			http.Error(w, "Mongo Error: "+err.Error(), 500)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "Record Added", "action": "Propagation Started"})
}