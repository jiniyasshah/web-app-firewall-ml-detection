package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/limiter"
	"web-app-firewall-ml-detection/internal/logger"

	"go.mongodb.org/mongo-driver/mongo"
)

// APIHandler holds dependencies for all HTTP endpoints
type APIHandler struct {
	MongoClient *mongo.Client
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter // [FIXED] Changed from IPRateLimiter to RateLimiter
	
	// Config
	MLURL     string
	OriginURL string
	DBName    string
	CollName  string

	// Active Rules (Mutex protected for hot-swapping)
	rulesMutex sync.RWMutex
	rules      []detector.WAFRule
}

// NewAPIHandler initializes the handler and loads initial rules
func NewAPIHandler(client *mongo.Client, proxy *httputil.ReverseProxy, limiter *limiter.RateLimiter, mlURL, originURL string) *APIHandler {
	h := &APIHandler{
		MongoClient: client,
		Proxy:       proxy,
		RateLimiter: limiter,
		MLURL:       mlURL,
		OriginURL:   originURL,
		DBName:      "waf",
		CollName:    "rules",
	}
	h.ReloadRules()
	return h
}

// ReloadRules fetches enabled rules from DB and updates the engine
func (h *APIHandler) ReloadRules() {
	h.rulesMutex.Lock()
	defer h.rulesMutex.Unlock()

	rules, err := database.LoadRules(h.MongoClient, h.DBName, h.CollName)
	if err != nil {
		log.Printf("Error reloading rules: %v", err)
		return
	}
	h.rules = rules
	log.Printf("♻️ Rules Reloaded. Active count: %d", len(h.rules))
}

// ---------------------------------------------------------
// 1. WAF CORE HANDLER
// ---------------------------------------------------------
func (h *APIHandler) WAFHandler(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" { clientIP = r.RemoteAddr }

	// Capture Body
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	fullReq := logger.FullRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: r.Header,
		Body:    string(bodyBytes),
	}

	// Rate Limit
	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	// Get Thread-Safe Rules
	h.rulesMutex.RLock()
	currentRules := h.rules
	h.rulesMutex.RUnlock()

	// Rule Check
	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, currentRules, limitReached)

	// ML Check (Skip if already blocked by critical rule)
	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	if !ruleBlock && ruleScore < 15 {
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, h.MLURL)
	}

	// Decision
	verdict, reason, source := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

	// Tags & Trigger Logic
	if mlTag != "" && mlTag != "Normal" && (isAnomaly || confidence > 0.60) {
		triggeredTags = append(triggeredTags, mlTag)
	}

	finalTrigger := rulePayload
	if source == "ML Engine" || (source == "Hybrid" && mlTrigger != "") {
		finalTrigger = mlTrigger
	}

	// Action
	switch verdict {
	case detector.Block:
		log.Printf("⛔ BLOCKED IP: %s | Source: %s | Reason: %s", clientIP, source, reason)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))
		return

	case detector.Monitor:
		log.Printf("⚠️ FLAGGED IP: %s | Source: %s | Reason: %s", clientIP, source, reason)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		h.Proxy.ServeHTTP(w, r)

	case detector.Allow:
		h.Proxy.ServeHTTP(w, r)
	}
}

// ---------------------------------------------------------
// 2. LOGGING HANDLERS (SSE & History)
// ---------------------------------------------------------
func (h *APIHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	logsCh := logger.GetBroadcastChannel()
	for {
		select {
		case entry := <-logsCh:
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			if f, ok := w.(http.Flusher); ok { f.Flush() }
		case <-r.Context().Done():
			return
		}
	}
}

func (h *APIHandler) LogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	logs, _ := logger.GetRecentLogs(50)
	json.NewEncoder(w).Encode(logs)
}

// ---------------------------------------------------------
// 3. RULE MANAGEMENT HANDLERS
// ---------------------------------------------------------
func (h *APIHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	rules, err := database.GetAllRules(h.MongoClient, h.DBName, h.CollName)
	if err != nil {
		http.Error(w, "Failed to fetch rules", 500)
		return
	}
	json.NewEncoder(w).Encode(rules)
}

func (h *APIHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "POST" { return }

	var rule detector.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	if err := database.AddRule(h.MongoClient, h.DBName, h.CollName, rule); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	h.ReloadRules() // Hot Reload
	w.WriteHeader(http.StatusCreated)
}

func (h *APIHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "POST" { return }

	var payload struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	if err := database.ToggleRule(h.MongoClient, h.DBName, h.CollName, payload.ID, payload.Enabled); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	h.ReloadRules() // Hot Reload
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------
// 4. SYSTEM STATUS HANDLER
// ---------------------------------------------------------
func (h *APIHandler) SystemStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	status := map[string]string{
		"gateway":   "online",
		"ml_scorer": "offline",
		"origin":    "offline",
		"database":  "offline",
	}

	// Check DB
	if err := h.MongoClient.Ping(context.Background(), nil); err == nil {
		status["database"] = "online"
	}

	// Check ML
	if checkHealth(h.MLURL) { // Basic GET request
		status["ml_scorer"] = "online"
	}

	// Check Origin
	if checkHealth(h.OriginURL) {
		status["origin"] = "online"
	}

	json.NewEncoder(w).Encode(status)
}

// Helper to check HTTP health
func checkHealth(urlStr string) bool {
	client := http.Client{Timeout: 2 * time.Second}
	// We assume a GET to the root or health endpoint checks availability
	resp, err := client.Get(urlStr)
	if err != nil { return false }
	defer resp.Body.Close()
	return true
}