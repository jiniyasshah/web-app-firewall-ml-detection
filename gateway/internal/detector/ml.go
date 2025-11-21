package detector

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type MLRequest struct {
	Path   string `json:"path"`
	Body   string `json:"body"`
	Length int    `json:"length"`
}

type MLResponse struct {
	IsAnomaly    bool    `json:"is_anomaly"`
	AnomalyScore float64 `json:"anomaly_score"`
}

// CheckML sends the request metadata to the Python ML Service
func CheckML(r *http.Request, mlURL string) (bool, float64) {
	// 1. Prepare Data
	// We need to read the body without consuming it (since we already read it in engine.go, 
	// we assume the caller has restored it or we read from the restored body)
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore immediately

	payload := MLRequest{
		Path:   r.URL.Path,
		Body:   string(bodyBytes),
		Length: len(bodyBytes),
	}

	jsonData, _ := json.Marshal(payload)

	// 2. Send to Python Service
	client := &http.Client{Timeout: 2 * time.Second} // Fail fast if ML is slow
	resp, err := client.Post(mlURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// If ML is down, Fail Open (Allow traffic) or Fail Closed (Block)
		// For a project, Log error and Allow is safer so you don't crash.
		return false, 0.0
	}
	defer resp.Body.Close()

	// 3. Parse Response
	var result MLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, 0.0
	}

	return result.IsAnomaly, result.AnomalyScore
}