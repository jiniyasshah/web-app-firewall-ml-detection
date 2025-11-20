package detector

import (
	"bytes"
	"io"
	"log"
	"net/http"
)

// CheckRequest is the main entry point for the WAF engine
func CheckRequest(r *http.Request, rules []WAFRule, isRateLimited bool) (int, []string, bool) {
	totalScore := 0
	var triggeredTags []string
	forceBlock := false

	// 1. Read Body Safely (and restore it)
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	
	// 2. Construct Context Variables once
	combinedPayload := r.URL.Path + " " + r.URL.RawQuery + " " + string(bodyBytes)
	paramCount := len(r.URL.Query())
	bodyLen := len(bodyBytes)

	// 3. Iterate Rules
	for _, rule := range rules {
		matched := true
		for _, cond := range rule.Conditions {
			// Evaluate every condition. If one fails, the whole rule fails.
			if !evaluate(cond, r, combinedPayload, paramCount, bodyLen, isRateLimited) {
				matched = false
				break
			}
		}

		// 4. Handle Match
		if matched {
			log.Printf("[WAF MATCH] Rule: %s (+%d)", rule.Name, rule.OnMatch.ScoreAdd)
			totalScore += rule.OnMatch.ScoreAdd
			triggeredTags = append(triggeredTags, rule.OnMatch.Tags...)
			
			if rule.OnMatch.HardBlock {
				forceBlock = true
			}
		}
	}

	return totalScore, triggeredTags, forceBlock
}

// evaluate checks a single condition against the request
func evaluate(cond Condition, r *http.Request, combined string, paramCount, bodyLen int, isRateLimited bool) bool {
	switch cond.Field {
	
	// --- REGEX FIELDS (Optimized) ---
	case "request.combined":
		// We trust 'database.LoadRules' compiled this. If nil, it won't match.
		if cond.CompiledRegex != nil {
			return cond.CompiledRegex.MatchString(combined)
		}

	case "request.headers.User-Agent":
		if cond.CompiledRegex != nil {
			return cond.CompiledRegex.MatchString(r.UserAgent())
		}

	// --- EXACT MATCH FIELDS ---
	case "request.method":
		if cond.Operator == "equals" {
			valStr, ok := cond.Value.(string)
			return ok && r.Method == valStr
		}

	// --- NUMERIC FIELDS ---
	case "meta.param_count":
		if cond.Operator == "gt" {
			return compareInt(cond.Value, paramCount)
		}

	case "meta.body_length":
		if cond.Operator == "gt" {
			return compareInt(cond.Value, bodyLen)
		}

	// --- BOOLEAN FIELDS ---
	case "meta.rate_limited":
		if cond.Operator == "equals_bool" {
			valBool, ok := cond.Value.(bool)
			// If rule says "true" and we are rate limited, return true
			return ok && (isRateLimited == valBool)
		}
	}

	return false
}

// compareInt handles the fact that Mongo might decode numbers as int32, int64, or float64
func compareInt(val interface{}, actual int) bool {
	switch v := val.(type) {
	case int32:
		return actual > int(v)
	case int64:
		return actual > int(v)
	case float64:
		return actual > int(v)
	case int:
		return actual > v
	}
	return false
}