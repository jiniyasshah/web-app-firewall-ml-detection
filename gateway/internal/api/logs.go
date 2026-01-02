package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/logger"
)

func (h *APIHandler) SecuredLogsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	// Fetch logs ONLY for domains owned by this user
	logs, err := database.GetLogsForUser(h.MongoClient, userID, 50)
	if err != nil {
		http.Error(w, "Failed to fetch logs", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(logs)
}

func (h *APIHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	logsCh := logger.GetBroadcastChannel()
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