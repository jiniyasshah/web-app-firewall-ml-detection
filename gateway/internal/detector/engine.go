package detector

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings" // [NEW] Required for TrimSpace and Contains

	"web-app-firewall-ml-detection/internal/models" // [CRITICAL] Import shared models
)

// CheckRequest now accepts []models.WAFRule instead of local WAFRule
func CheckRequest(r *http.Request, rules []models.WAFRule, isRateLimited bool) (int, []string, bool, string) {
	totalScore := 0
	var triggeredTags []string
	forceBlock := false
	finalTriggerPayload := "" // [NEW] Tracks what actually triggered the block

	// 1. Read Body
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	bodyStr := string(bodyBytes) // [NEW] Keep string version for evaluation

	// 2. Construct Payload
	decodedPath, _ := url.QueryUnescape(r.URL.Path)
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)
	// [FIXED] Trim space to prevent empty paths from just being " / "
	combinedPayload := strings.TrimSpace(decodedPath + " " + decodedQuery + " " + bodyStr)

	paramCount := len(r.URL.Query())
	bodyLen := len(bodyBytes)

	// 3. Iterate Rules
	for _, rule := range rules {
		matched := true
		var ruleTrigger string // Tracks the trigger for this specific rule

		for _, cond := range rule.Conditions {
			// [FIXED] evaluate now returns (match bool, triggerValue string)
			match, triggerVal := evaluate(cond, r, combinedPayload, bodyStr, paramCount, bodyLen, isRateLimited)
			if !match {
				matched = false
				break
			}
			
			// Capture the meaningful string that matched
			if triggerVal != "" {
				ruleTrigger = triggerVal
			}
		}

		if matched {
			log.Printf("[WAF MATCH] Rule: %s (+%d) | Trigger: %s", rule.Name, rule.OnMatch.ScoreAdd, ruleTrigger)
			totalScore += rule.OnMatch.ScoreAdd
			triggeredTags = append(triggeredTags, rule.OnMatch.Tags...)

			// Save the specific string that caused the flag/block to send to the Logger
			if finalTriggerPayload == "" || rule.OnMatch.HardBlock {
				finalTriggerPayload = ruleTrigger
			}

			if rule.OnMatch.HardBlock {
				forceBlock = true
			}
		}
	}

	// [FIXED] Fallback to the full payload if no specific string was caught
	if finalTriggerPayload == "" {
		finalTriggerPayload = combinedPayload
	}

	return totalScore, triggeredTags, forceBlock, finalTriggerPayload
}

// evaluate now returns (bool: Did it match?, string: What exactly matched?)
func evaluate(cond models.Condition, r *http.Request, combined string, bodyStr string, paramCount, bodyLen int, isRateLimited bool) (bool, string) {
	switch cond.Field {
	
	case "request.combined":
		if checkOperator(cond, combined) {
			return true, combined
		}
	
	case "request.headers.User-Agent":
		ua := r.UserAgent()
		if checkOperator(cond, ua) {
			return true, ua // [FIXED] Return the actual User-Agent string!
		}

	case "path":
		if checkOperator(cond, r.URL.Path) {
			return true, r.URL.Path
		}

	case "query":
		if checkOperator(cond, r.URL.RawQuery) {
			return true, r.URL.RawQuery
		}

	case "body":
		if checkOperator(cond, bodyStr) {
			return true, bodyStr
		}

	case "request.method":
		if checkOperator(cond, r.Method) {
			return true, r.Method
		}

	case "meta.param_count":
		if cond.Operator == "gt" && compareInt(cond.Value, paramCount) {
			return true, "High Parameter Count"
		}

	case "meta.body_length":
		if cond.Operator == "gt" && compareInt(cond.Value, bodyLen) {
			return true, "Large Body Payload"
		}

	case "meta.rate_limited":
		if cond.Operator == "equals" {
			valBool, ok := cond.Value.(bool)
			if ok && isRateLimited == valBool {
				return true, "Rate Limit Exceeded"
			}
		}
	}
	
	return false, ""
}

// [NEW] Helper to seamlessly evaluate strings against Regex, Equals, and Contains
func checkOperator(cond models.Condition, target string) bool {
	// 1. Regex Match
	if cond.Operator == "regex" && cond.CompiledRegex != nil {
		return cond.CompiledRegex.MatchString(target)
	}
	
	// Ensure value is a string for Equals/Contains
	valStr, ok := cond.Value.(string)
	if !ok {
		return false
	}

	// 2. Exact Match
	if cond.Operator == "equals" {
		return target == valStr
	}
	
	// 3. Substring Match
	if cond.Operator == "contains" {
		return strings.Contains(target, valStr)
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