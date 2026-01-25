package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/proxy"
	"web-app-firewall-ml-detection/internal/utils"

	"go.mongodb.org/mongo-driver/mongo"
)

// ComponentStatus struct for System Status API
type ComponentStatus struct {
	Status  string `json:"status"`
	CPU     string `json:"cpu"`
	Memory  string `json:"memory"`
	Network string `json:"network"`
}

type SystemHandler struct {
	MongoClient *mongo.Client
	Cfg         *config.Config
	WAF         *proxy.WAFHandler // Needed to get RPM
}

func NewSystemHandler(client *mongo.Client, cfg *config.Config, waf *proxy.WAFHandler) *SystemHandler {
	return &SystemHandler{
		MongoClient: client,
		Cfg:         cfg,
		WAF:         waf,
	}
}

func (h *SystemHandler) GetSystemStatus(w http.ResponseWriter, r *http.Request) {
	statusMap := make(map[string]ComponentStatus)

	// 1. GATEWAY STATS (Self)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	currentRPM := h.WAF.GetRPM()

	statusMap["gateway"] = ComponentStatus{
		Status:  "Online",
		Memory:  fmt.Sprintf("%v MB", m.Alloc/1024/1024),
		CPU:     fmt.Sprintf("%d Goroutines", runtime.NumGoroutine()),
		Network: fmt.Sprintf("%d Req/min", currentRPM),
	}

	// 2. DATABASE STATS
	if err := h.MongoClient.Ping(context.Background(), nil); err == nil {
		statusMap["database"] = ComponentStatus{
			Status:  "Online",
			Memory:  "Managed (External)",
			CPU:     "Managed (External)",
			Network: "N/A",
		}
	} else {
		statusMap["database"] = ComponentStatus{
			Status:  "Offline",
			Memory:  "0 MB",
			CPU:     "0%",
			Network: "0 Req/min",
		}
	}

	// 3. ML SCORER STATS
	statusMap["ml_scorer"] = h.fetchRemoteHealth(h.Cfg.MLURL)

	utils.WriteSuccess(w, statusMap, http.StatusOK)
}

// Helper to fetch rich stats from Python services
func (h *SystemHandler) fetchRemoteHealth(baseURL string) ComponentStatus {
	rootURL := baseURL
	if len(rootURL) > 0 && rootURL[len(rootURL)-1] == '/' {
		rootURL = rootURL[:len(rootURL)-1]
	}
	if len(rootURL) > 8 && rootURL[len(rootURL)-8:] == "/predict" {
		rootURL = rootURL[:len(rootURL)-8]
	}

	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(rootURL + "/health")
	if err != nil {
		return ComponentStatus{
			Status:  "Offline",
			Memory:  "0 MB",
			CPU:     "0%",
			Network: "0 Req/min",
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ComponentStatus{
			Status:  "Error",
			Memory:  "Unknown",
			CPU:     "Unknown",
			Network: "0 Req/min",
		}
	}

	var pythonStats struct {
		Status  string `json:"status"`
		CPU     string `json:"cpu"`
		Memory  string `json:"memory"`
		Network string `json:"network"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&pythonStats); err != nil {
		return ComponentStatus{
			Status:  "Online",
			Memory:  "Unknown",
			CPU:     "Unknown",
			Network: "Unknown",
		}
	}

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