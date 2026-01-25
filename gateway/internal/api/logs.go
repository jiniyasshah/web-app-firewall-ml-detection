package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/logger"
	"web-app-firewall-ml-detection/internal/utils"

	"go.mongodb.org/mongo-driver/mongo"
)

type LogHandler struct {
	MongoClient *mongo.Client
}

func NewLogHandler(client *mongo.Client) *LogHandler {
	return &LogHandler{MongoClient: client}
}

func (h *LogHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	query := r.URL.Query()
	domainID := query.Get("domain_id")
	
	pageStr := query.Get("page")
	page, _ := strconv.ParseInt(pageStr, 10, 64)
	if page < 1 { page = 1 }

	limitStr := query.Get("limit")
	limit, _ := strconv.ParseInt(limitStr, 10, 64)
	if limit < 1 { limit = 20 }

	filter := database.LogFilter{
		UserID:   userID,
		DomainID: domainID,
		Page:     page,
		Limit:    limit,
	}

	result, err := database.GetLogs(h.MongoClient, filter)
	if err != nil {
		utils.WriteError(w, "Failed to fetch logs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	utils.WriteSuccess(w, result, http.StatusOK)
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