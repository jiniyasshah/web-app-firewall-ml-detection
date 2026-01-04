package detector

import (
	"bytes"
	"encoding/json"
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

// Update signature to accept bodyBytes directly
func CheckML(r *http.Request, bodyBytes []byte, mlURL string) (bool, float64, string, string) {
	
	// FIX 1: Send the Full URI (Path + Query) so ML sees "?id=<script>"
	fullPath := r.URL.Path
	if r.URL.RawQuery != "" {
		fullPath += "?" + r.URL.RawQuery
	}

	// FIX 2: Use the bytes passed in. Do not touch r.Body again.
	payload := MLRequest{
		Path:   fullPath,
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