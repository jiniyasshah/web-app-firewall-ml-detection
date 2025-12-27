package api

import (
	"log"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/limiter"

	"go.mongodb.org/mongo-driver/mongo"
)

// Nameservers for random generation
var nsNames = []string{"alice", "bob", "charlie", "david", "eve", "mallory", "oscar", "peggy", "sybil", "trent"}

// APIHandler holds all dependencies
type APIHandler struct {
	MongoClient *mongo.Client
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter

	// Config
	MLURL     string
	OriginURL string
	DBName    string
	CollName  string

	// Active Rules (Mutex protected for hot-swapping)
	rulesMutex sync.RWMutex
	rules      []detector.WAFRule

	// [NEW] Traffic Stats
	reqCount uint64 // Atomic counter for current minute
	rpm      uint64 // Stored value of last minute's requests
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

	// Start Background Stats Tracker
	go h.startStatsTicker()

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

// Background Ticker to calculate RPM
func (h *APIHandler) startStatsTicker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Swap current count to RPM and reset counter to 0
		count := atomic.SwapUint64(&h.reqCount, 0)
		atomic.StoreUint64(&h.rpm, count)
	}
}