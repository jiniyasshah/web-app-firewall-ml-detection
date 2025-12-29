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
	IsAnomaly      bool    `json:"is_anomaly"`
	AnomalyScore   float64 `json:"anomaly_score"`
	AttackType     string  `json:"attack_type"`
	TriggerContent string  `json:"trigger_content"`
}

// CheckML sends the request to the Python ML service
func CheckML(r *http.Request, mlURL string) (bool, float64, string, string) {
	// Re-read body (it was restored in WAFHandler)
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	payload := MLRequest{
		Path:   r.URL.Path,
		Body:   string(bodyBytes),
		Length: len(bodyBytes),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return false, 0.0, "", ""
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(mlURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// Log error in production
		return false, 0.0, "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0.0, "", ""
	}

	var result MLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, 0.0, "", ""
	}

	return result.IsAnomaly, result.AnomalyScore, result.AttackType, result.TriggerContent
}