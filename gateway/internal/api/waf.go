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

func (h *APIHandler) WAFHandler(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&h.reqCount, 1)

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" { clientIP = r.RemoteAddr }

	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Determine Rules for this Host
	// Host usually contains port (e.g. "example.com:8080"), strip it for map lookup
	host := r.Host
	if strings.Contains(host, ":") {
		h, _, _ := net.SplitHostPort(host)
		if h != "" { host = h }
	}

	h.rulesMutex.RLock()
	// Lookup optimized rule set for this specific domain
	currentRules, exists := h.domainRules[host]
	if !exists {
		// Fallback for unknown domains (or use empty slice to fail open)
		currentRules = h.globalFallback 
	}
	h.rulesMutex.RUnlock()

	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	// Engine now processes the customized list
	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, currentRules, limitReached)

	// ... [Rest of the logic (ML check, Decision, Logging) remains exactly the same] ...
	
	// Copy the rest of the file from your existing waf.go starting from "var isAnomaly bool"
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
	
	fullReq := logger.FullRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: r.Header,
		Body:    string(bodyBytes),
	}

	finalTrigger := rulePayload
	if source == "ML Engine" || (source == "Hybrid" && mlTrigger != "") {
		finalTrigger = mlTrigger
	}

	switch verdict {
	case detector.Block:
		log.Printf("⛔ BLOCKED IP: %s | Host: %s | Source: %s | Reason: %s", clientIP, host, source, reason)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))
		return

	case detector.Monitor:
		log.Printf("⚠️ FLAGGED IP: %s | Host: %s | Source: %s", clientIP, host, source)
		logger.LogAttack(clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		h.Proxy.ServeHTTP(w, r)

	case detector.Allow:
		h.Proxy.ServeHTTP(w, r)
	}
}