package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// ComponentStatus struct for System Status API
type ComponentStatus struct {
	Status  string `json:"status"`
	CPU     string `json:"cpu,omitempty"`
	Memory  string `json:"memory,omitempty"`
	Network string `json:"network,omitempty"` // For RPM
}

func (h *APIHandler) SystemStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	statusMap := make(map[string]ComponentStatus)

	// 1. GATEWAY STATS (Self)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Fetch current RPM safely
	currentRPM := atomic.LoadUint64(&h.rpm)

	statusMap["gateway"] = ComponentStatus{
		Status:  "online",
		Memory:  fmt.Sprintf("%v MB", m.Alloc/1024/1024),
		CPU:     fmt.Sprintf("Goroutines: %d", runtime.NumGoroutine()),
		Network: fmt.Sprintf("%d Req/min", currentRPM),
	}

	// 2. DATABASE STATS
	if err := h.MongoClient.Ping(context.Background(), nil); err == nil {
		statusMap["database"] = ComponentStatus{Status: "online", Memory: "Managed", CPU: "Managed"}
	} else {
		statusMap["database"] = ComponentStatus{Status: "offline"}
	}

	// 3. ML SCORER STATS
	statusMap["ml_scorer"] = fetchRemoteHealth(h.MLURL)

	// 4. ORIGIN STATS - [REMOVED as requested]
	// We don't check the user's server health anymore.

	json.NewEncoder(w).Encode(statusMap)
}

// Helper to fetch rich stats from Python services
func fetchRemoteHealth(baseURL string) ComponentStatus {
	rootURL := baseURL
	// Trim path to find base URL if needed
	if len(rootURL) > 0 && rootURL[len(rootURL)-1] == '/' {
		rootURL = rootURL[:len(rootURL)-1]
	}
	if len(rootURL) > 8 && rootURL[len(rootURL)-8:] == "/predict" {
		rootURL = rootURL[:len(rootURL)-8]
	}

	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(rootURL + "/health")
	if err != nil {
		return ComponentStatus{Status: "offline"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ComponentStatus{Status: "error"}
	}

	var stats ComponentStatus
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		// Fallback if the service returns simple 200 OK without JSON stats
		return ComponentStatus{Status: "online", CPU: "Unknown", Memory: "Unknown"}
	}
	return stats
}