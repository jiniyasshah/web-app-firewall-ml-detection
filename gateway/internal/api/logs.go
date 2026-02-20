package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/logger"
	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/utils"

	"go.mongodb.org/mongo-driver/mongo"
)

type LogHandler struct {
	MongoClient *mongo.Client
}

func NewLogHandler(client *mongo.Client) *LogHandler {
	return &LogHandler{MongoClient: client}
}

type PaginatedLogsResponse struct {
	Logs        []models.AttackLog `json:"logs"`
	Total       int64              `json:"total"`
	Page        int                `json:"page"`
	Limit       int                `json:"limit"`
	TotalPages  int                `json:"total_pages"`
	TotalEvents int64              `json:"total_events"` // [NEW]
	Blocked     int64              `json:"blocked"`      // [NEW]
	Flagged     int64              `json:"flagged"`      // [NEW]
}

func (h *LogHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 { page = 1 }
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 { limit = 20 }

	// Read new filters from URL
	domainID := r.URL.Query().Get("domain_id")
	action := r.URL.Query().Get("action")
	ip := r.URL.Query().Get("ip")
    source := r.URL.Query().Get("source")

	// [UPDATED] Pass source to GetLogs
	logs, totalFiltered, totalEvents, blocked, flagged, err := database.GetLogs(h.MongoClient, domainID, page, limit, action, ip, source)
	if err != nil {
		utils.WriteError(w, "Failed to fetch logs", http.StatusInternalServerError)
		return
	}

	totalPages := int(totalFiltered) / limit
	if int(totalFiltered)%limit != 0 {
		totalPages++
	}

	response := PaginatedLogsResponse{
		Logs:        logs,
		Total:       totalFiltered,
		Page:        page,
		Limit:       limit,
		TotalPages:  totalPages,
		TotalEvents: totalEvents, // Include accurate stats
		Blocked:     blocked,     // Include accurate stats
		Flagged:     flagged,     // Include accurate stats
	}

	utils.WriteSuccess(w, response, http.StatusOK)
}

func (h *LogHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	logsCh := logger.GetBroadcastChannel()
	
	// Flush immediately to establish connection
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	for {
		select {
		case entry := <-logsCh:
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}