// type: uploaded file
// fileName: jiniyasshah/web-app-firewall-ml-detection/web-app-firewall-ml-detection-test/gateway/internal/api/logs.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/logger"
)

func (h *APIHandler) SecuredLogsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	// 1. Parse Query Params
	query := r.URL.Query()
	domainID := query.Get("domain_id")
	
	pageStr := query.Get("page")
	page, _ := strconv.ParseInt(pageStr, 10, 64)
	if page < 1 { page = 1 }

	limitStr := query.Get("limit")
	limit, _ := strconv.ParseInt(limitStr, 10, 64)
	if limit < 1 { limit = 20 }

	// 2. Fetch Logs via Database Helper
	filter := database.LogFilter{
		UserID:   userID,
		DomainID: domainID,
		Page:     page,
		Limit:    limit,
	}

	result, err := database.GetLogs(h.MongoClient, filter)
	if err != nil {
		h.WriteJSONError(w, "Failed to fetch logs: " + err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Return Standardized JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
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