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
// Unified format: Status | CPU | Memory | Network (Req/min)
type ComponentStatus struct {
	Status  string `json:"status"`
	CPU     string `json:"cpu"`
	Memory  string `json:"memory"`
	Network string `json:"network"` 
}

func (h *APIHandler) SystemStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	statusMap := make(map[string]ComponentStatus)

	// 1.GATEWAY STATS (Self)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	currentRPM := atomic.LoadUint64(&h.rpm)

	statusMap["gateway"] = ComponentStatus{
		Status:  "Online",
		Memory:  fmt.Sprintf("%v MB", m.Alloc/1024/1024),
		CPU:     fmt.Sprintf("%d Goroutines", runtime.NumGoroutine()),
		Network: fmt.Sprintf("%d Req/min", currentRPM),
	}

	// 2.DATABASE STATS
	// MongoDB manages its own resources, so we mark CPU/Mem as "Managed" 
	// but we could query serverStatus if strict stats were needed.
	if err := h.MongoClient.Ping(context.Background(), nil); err == nil {
		statusMap["database"] = ComponentStatus{
			Status:  "Online", 
			Memory:  "Managed (External)", 
			CPU:     "Managed (External)",
			Network: "N/A", // DB doesn't track "Req/min" in this context easily
		}
	} else {
		statusMap["database"] = ComponentStatus{
			Status: "Offline",
			Memory: "0 MB",
			CPU:    "0%",
			Network: "0 Req/min",
		}
	}

	// 3.ML SCORER STATS
	statusMap["ml_scorer"] = fetchRemoteHealth(h.MLURL)

	json.NewEncoder(w).Encode(statusMap)
}

// Helper to fetch rich stats from Python services
func fetchRemoteHealth(baseURL string) ComponentStatus {
	rootURL := baseURL
	if len(rootURL) > 0 && rootURL[len(rootURL)-1] == '/' {
		rootURL = rootURL[:len(rootURL)-1]
	}
	// Handle if user passed the full predict URL by mistake
	if len(rootURL) > 8 && rootURL[len(rootURL)-8:] == "/predict" {
		rootURL = rootURL[:len(rootURL)-8]
	}

	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(rootURL + "/health")
	if err != nil {
		return ComponentStatus{
			Status: "Offline", 
			Memory: "0 MB", 
			CPU: "0%", 
			Network: "0 Req/min",
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ComponentStatus{
			Status: "Error", 
			Memory: "Unknown", 
			CPU: "Unknown", 
			Network: "0 Req/min",
		}
	}

	// Define a struct matching the Python JSON response keys
	// Python sends: {"status": "online", "cpu": "X%", "memory": "Y MB", "network": "Z Req/min"}
	var pythonStats struct {
		Status  string `json:"status"`
		CPU     string `json:"cpu"`
		Memory  string `json:"memory"`
		Network string `json:"network"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&pythonStats); err != nil {
		return ComponentStatus{
			Status: "Online", 
			Memory: "Unknown", 
			CPU: "Unknown", 
			Network: "Unknown",
		}
	}

	// Capitalize status to match Go convention
	status := "Online"
	if pythonStats.Status != "online" {
		status = pythonStats.Status
	}

	return ComponentStatus{
		Status:  status,
		CPU:     pythonStats.CPU,
		Memory:  pythonStats.Memory,
		Network: pythonStats.Network,
	}
}