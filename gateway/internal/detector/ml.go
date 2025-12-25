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
	TriggerContent string  `json:"trigger_content"` // [NEW]
}

// CheckML returns: (IsAnomaly, Score, AttackType, TriggerContent)
func CheckML(r *http.Request, mlURL string) (bool, float64, string, string) {
	// 1. Prepare Data
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	payload := MLRequest{
		Path:   r.URL.Path,
		Body:   string(bodyBytes),
		Length: len(bodyBytes),
	}

	jsonData, _ := json.Marshal(payload)

	// 2. Send to Python Service
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(mlURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, 0.0, "", ""
	}
	defer resp.Body.Close()

	// 3. Parse Response
	var result MLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, 0.0, "", ""
	}

	return result.IsAnomaly, result.AnomalyScore, result.AttackType, result.TriggerContent
}