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

// Helper to extract IP
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
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	host := r.Host
	if strings.Contains(host, ":") {
		if hostname, _, err := net.SplitHostPort(host); err == nil {
			host = hostname
		}
	}

	// [UPDATED] Lookup Rules AND Domain Metadata (UserID/DomainID)
	h.rulesMutex.RLock()
	currentRules, rulesExist := h.domainRules[host]
	domainInfo, domainExists := h.domainMap[host] // Use the new cache
	h.rulesMutex.RUnlock()

	// 1. UNCONFIGURED DOMAIN CHECK
	if !rulesExist || !domainExists {
		log.Printf("⚠️ Unknown Domain Accessed: %s from %s. Returning Custom 404.", host, clientIP)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		if len(h.UnconfiguredPage) > 0 {
			w.Write(h.UnconfiguredPage)
		} else {
			w.Write([]byte("Domain not configured"))
		}
		return
	}

	// Extract IDs for Logging
	userID := domainInfo.UserID
	domainID := domainInfo.ID

	// Rate Limiting
	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	// 1. Rule Engine Check
	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, currentRules, limitReached)

	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	// 2. ML Engine Check
	if !ruleBlock && ruleScore < 15 {
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, bodyBytes, h.MLURL)
	}

	// 3. Final Decision
	verdict, reason, source := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

	if mlTag != "" && mlTag != "Normal" && (isAnomaly || confidence > 0.60) {
		triggeredTags = append(triggeredTags, mlTag)
	}

	finalTrigger := rulePayload
	if source == "ML Engine" || (source == "Hybrid" && mlTrigger != "") {
		finalTrigger = mlTrigger
	}

	// 4. Logging & Action
	
	// [FIX] Ensure headers map is not nil and include Host
headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[k] = v
	}
	headers["Host"] = []string{host}

	// [FIXED] logger.FullRequest -> detector.FullRequest
	fullReq := detector.FullRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: headers,
		Body:    string(bodyBytes),
	}

	// [UPDATED] LogAttack call now includes userID and domainID
	switch verdict {
	case detector.Block:
		log.Printf("⛔ BLOCKED IP: %s | Host: %s | Reason: %s", clientIP, host, reason)
		logger.LogAttack(userID, domainID, clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))

	case detector.Monitor:
		log.Printf("⚠️ FLAGGED IP: %s | Host: %s", clientIP, host)
		logger.LogAttack(userID, domainID, clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		h.Proxy.ServeHTTP(w, r)

	case detector.Allow:
		h.Proxy.ServeHTTP(w, r)
	}
}