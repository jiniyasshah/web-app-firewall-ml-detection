package detector

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"

	"web-app-firewall-ml-detection/internal/models" // [CRITICAL] Import shared models
)

// CheckRequest now accepts []models.WAFRule instead of local WAFRule
func CheckRequest(r *http.Request, rules []models.WAFRule, isRateLimited bool) (int, []string, bool, string) {
	totalScore := 0
	var triggeredTags []string
	forceBlock := false

	// 1. Read Body
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 2. Construct Payload
	decodedPath, _ := url.QueryUnescape(r.URL.Path)
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)
	combinedPayload := decodedPath + " " + decodedQuery + " " + string(bodyBytes)

	paramCount := len(r.URL.Query())
	bodyLen := len(bodyBytes)

	// 3. Iterate Rules
	for _, rule := range rules {
		matched := true
		for _, cond := range rule.Conditions {
			// Pass models.Condition to evaluate
			if !evaluate(cond, r, combinedPayload, paramCount, bodyLen, isRateLimited) {
				matched = false
				break
			}
		}

		if matched {
			log.Printf("[WAF MATCH] Rule: %s (+%d)", rule.Name, rule.OnMatch.ScoreAdd)
			totalScore += rule.OnMatch.ScoreAdd
			triggeredTags = append(triggeredTags, rule.OnMatch.Tags...)

			if rule.OnMatch.HardBlock {
				forceBlock = true
			}
		}
	}

	return totalScore, triggeredTags, forceBlock, combinedPayload
}

// evaluate now accepts models.Condition
func evaluate(cond models.Condition, r *http.Request, combined string, paramCount, bodyLen int, isRateLimited bool) bool {
	switch cond.Field {
	case "request.combined":
		if cond.CompiledRegex != nil {
			return cond.CompiledRegex.MatchString(combined)
		}
	case "request.headers.User-Agent":
		if cond.CompiledRegex != nil {
			return cond.CompiledRegex.MatchString(r.UserAgent())
		}
	case "request.method":
		if cond.Operator == "equals" {
			valStr, ok := cond.Value.(string)
			return ok && r.Method == valStr
		}
	case "meta.param_count":
		if cond.Operator == "gt" {
			return compareInt(cond.Value, paramCount)
		}
	case "meta.body_length":
		if cond.Operator == "gt" {
			return compareInt(cond.Value, bodyLen)
		}
	case "meta.rate_limited":
		if cond.Operator == "equals" {
			valBool, ok := cond.Value.(bool)
			return ok && isRateLimited == valBool
		}
	}
	return false
}

// Helper to safely compare interface{} (json numbers) with int
func compareInt(val interface{}, actual int) bool {
	switch v := val.(type) {
	case float64: // JSON numbers are often float64
		return float64(actual) > v
	case int:
		return actual > v
	}
	return false
}
