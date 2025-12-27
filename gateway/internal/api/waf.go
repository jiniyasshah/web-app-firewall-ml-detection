package api

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"

	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/logger"
)

func (h *APIHandler) WAFHandler(w http.ResponseWriter, r *http.Request) {
	// [NEW] Increment Global Request Counter
	atomic.AddUint64(&h.reqCount, 1)

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	fullReq := logger.FullRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: r.Header,
		Body:    string(bodyBytes),
	}

	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	h.rulesMutex.RLock()
	currentRules := h.rules
	h.rulesMutex.RUnlock()

	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, currentRules, limitReached)

	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	if !ruleBlock && ruleScore < 15 {
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, h.MLURL)
	}

	verdict, reason, source := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

	if mlTag != "" && mlTag != "Normal" && (isAnomaly || confidence > 0.60) {
		triggeredTags = append(triggeredTags, mlTag)
	}

	finalTrigger := rulePayload
	if source == "ML Engine" || (source == "Hybrid" && mlTrigger != "") {
		finalTrigger = mlTrigger
	}

	switch verdict {
	case detector.Block:
		log.Printf("⛔ BLOCKED IP: %s | Source: %s | Reason: %s", clientIP, source, reason)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))
		return

	case detector.Monitor:
		log.Printf("⚠️ FLAGGED IP: %s | Source: %s | Reason: %s", clientIP, source, reason)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		h.Proxy.ServeHTTP(w, r)

	case detector.Allow:
		h.Proxy.ServeHTTP(w, r)
	}
}