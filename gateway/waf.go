package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// WAFRule struct with BSON tags for MongoDB
type WAFRule struct {
	ID         string      `bson:"_id" json:"_id"`
	Name       string      `bson:"name" json:"name"`
	Enabled    bool        `bson:"enabled" json:"enabled"`
	Conditions []Condition `bson:"conditions" json:"conditions"`
	OnMatch    Action      `bson:"on_match" json:"on_match"`
}

type Condition struct {
	Field    string      `bson:"field" json:"field"`
	Operator string      `bson:"operator" json:"operator"`
	Value    interface{} `bson:"value" json:"value"`
}

type Action struct {
	ScoreAdd int      `bson:"score_add" json:"score_add"`
	Tags     []string `bson:"tags" json:"tags"`
}

type RateLimiter struct {
    visits map[string][]time.Time
    mu     sync.Mutex
    limit  int           // Max requests
    window time.Duration // Time window
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
    return &RateLimiter{
        visits: make(map[string][]time.Time),
        limit:  limit,
        window: window,
    }
}

func (rl *RateLimiter) IsRateLimited(ip string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    now := time.Now()
    windowStart := now.Add(-rl.window)

    // Filter out old requests
    var activeVisits []time.Time
    for _, v := range rl.visits[ip] {
        if v.After(windowStart) {
            activeVisits = append(activeVisits, v)
        }
    }
    
    // Record current visit
    activeVisits = append(activeVisits, now)
    rl.visits[ip] = activeVisits

    return len(activeVisits) > rl.limit
}

// ConnectDB establishes a connection to MongoDB
func ConnectDB(uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	return client, nil
}

// LoadRulesFromDB fetches enabled rules from MongoDB
func LoadRulesFromDB(client *mongo.Client, dbName, collName string) ([]WAFRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database(dbName).Collection(collName)
	
	// Filter: Only fetch enabled rules
	filter := bson.M{"enabled": true}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var rules []WAFRule
	if err = cursor.All(ctx, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// CheckRequest inspects the HTTP request against the rules (Logic remains mostly the same)
func CheckRequest(r *http.Request, rules []WAFRule, isRateLimited bool) (int, []string) {
	totalScore := 0
	var triggeredTags []string

	// 1. Read and Restore Body
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	bodyString := string(bodyBytes)

	combinedPayload := r.URL.Path + " " + r.URL.RawQuery + " " + bodyString
	paramCount := len(r.URL.Query())
	bodyLen := len(bodyBytes)

	for _, rule := range rules {
        matched := true
        for _, cond := range rule.Conditions {
            // Pass isRateLimited to evaluateCondition
            if !evaluateCondition(cond, r, combinedPayload, paramCount, bodyLen, isRateLimited) {
                matched = false
                break
            }
        }
		if matched {
			log.Printf("[WAF] MATCH: %s (Adding Score: %d)", rule.Name, rule.OnMatch.ScoreAdd)
			totalScore += rule.OnMatch.ScoreAdd
			triggeredTags = append(triggeredTags, rule.OnMatch.Tags...)
		}
	}

	return totalScore, triggeredTags
}

func evaluateCondition(cond Condition, r *http.Request, combined string, paramCount int, bodyLen int, isRateLimited bool) bool {
	switch cond.Field {
	case "request.combined":
		if cond.Operator == "regex" {
			valStr, ok := cond.Value.(string)
			if !ok { return false }
			re, err := regexp.Compile(valStr)
			if err != nil { return false }
			return re.MatchString(combined)
		}
	case "request.headers.User-Agent":
		ua := r.UserAgent()
		if cond.Operator == "regex" {
			valStr, ok := cond.Value.(string)
			if !ok { return false }
			re, err := regexp.Compile(valStr)
			if err != nil { return false }
			return re.MatchString(ua)
		}
	case "request.method":
		if cond.Operator == "equals" {
			valStr, ok := cond.Value.(string)
			return ok && r.Method == valStr
		}
	case "meta.param_count":
		if cond.Operator == "gt" {
			// Handle multiple number types (Mongo might return int32, int64, or float64)
			return compareInt(cond.Value, paramCount)
		}
	case "meta.rate_limited":
        if cond.Operator == "equals_bool" {
            valBool, ok := cond.Value.(bool)
            // If rule says "true" and we are rate limited, return true
            return ok && (isRateLimited == valBool)
        }	
	case "meta.body_length":
		if cond.Operator == "gt" {
			return compareInt(cond.Value, bodyLen)
		}
	}
	return false
}

// Helper to handle Mongo number types
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