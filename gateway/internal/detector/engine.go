package detector

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
)

// CheckRequest is the main entry point for the WAF engine
func CheckRequest(r *http.Request, rules []WAFRule, isRateLimited bool) (int, []string, bool) {
    totalScore := 0
    var triggeredTags []string
    forceBlock := false

    // 1. Read Body
    bodyBytes, _ := io.ReadAll(r.Body)
    r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
    
    // 2. DECODE & CONSTRUCT PAYLOAD (The Fix)
    // We decode the query to turn "%7B" back into "{" so regex matches
    decodedPath, _ := url.QueryUnescape(r.URL.Path)
    decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)
    
    // We combine BOTH the Raw and Decoded versions to catch everything
    // Some attacks hide in Raw (e.g., double encoding), some in Decoded.
    // For this simple WAF, checking the Decoded version is most important.
    combinedPayload := decodedPath + " " + decodedQuery + " " + string(bodyBytes)
    
    paramCount := len(r.URL.Query())
    bodyLen := len(bodyBytes)

    // 3. Iterate Rules ... (Rest of the code is the same)

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