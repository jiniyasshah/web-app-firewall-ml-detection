package api

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/logger"
)

// Helper to extract IP from X-Forwarded-For or RemoteAddr
func getRealIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (h *APIHandler) WAFHandler(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&h.reqCount, 1)

	clientIP := getRealIP(r)

	// Buffer Body for Analysis & Forwarding
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Determine Rules for this Host
	// Strip port if present (e.g. "example.com:8080" -> "example.com")
	host := r.Host
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}

	h.rulesMutex.RLock()
	currentRules, exists := h.domainRules[host]
	if !exists {
		currentRules = h.globalFallback
	}
	h.rulesMutex.RUnlock()

	// Rate Limiting
	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	// 1. Rule Engine Check
	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, currentRules, limitReached)

	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	// 2. ML Engine Check (Only if not already blocked and score is low)
	if !ruleBlock && ruleScore < 15 {
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, h.MLURL)
	}

	// 3. Final Decision
	verdict, reason, source := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

	// Merge ML tags if relevant
	if mlTag != "" && mlTag != "Normal" && (isAnomaly || confidence > 0.60) {
		triggeredTags = append(triggeredTags, mlTag)
	}

	finalTrigger := rulePayload
	if source == "ML Engine" || (source == "Hybrid" && mlTrigger != "") {
		finalTrigger = mlTrigger
	}

	// 4. Logging & Action
	fullReq := logger.FullRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: r.Header,
		Body:    string(bodyBytes),
	}

	switch verdict {
	case detector.Block:
		log.Printf("⛔ BLOCKED IP: %s | Host: %s | Source: %s | Reason: %s", clientIP, host, source, reason)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))

	case detector.Monitor:
		log.Printf("⚠️ FLAGGED IP: %s | Host: %s | Source: %s", clientIP, host, source)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		h.Proxy.ServeHTTP(w, r)

	case detector.Allow:
		h.Proxy.ServeHTTP(w, r)
	}
}