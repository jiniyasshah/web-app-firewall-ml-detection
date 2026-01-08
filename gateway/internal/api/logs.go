package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/logger"
	"web-app-firewall-ml-detection/pkg/middleware"
	"web-app-firewall-ml-detection/pkg/response"
)

func (h *APIHandler) SecuredLogsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}

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
		response.InternalServerError(w, "Failed to fetch logs: " + err.Error())
		return
	}

	// 3. Return Standardized JSON
	response.JSON(w, result, http.StatusOK)
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