package logger

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// [UPDATED] JSON tags added for Frontend API
type FullRequest struct {
	Method  string              `bson:"method" json:"method"`
	URL     string              `bson:"url" json:"url"`
	Headers map[string][]string `bson:"headers" json:"headers"`
	Body    string              `bson:"body" json:"body"`
}

type AttackLog struct {
	Timestamp      time.Time   `bson:"timestamp" json:"timestamp"`
	IP             string      `bson:"ip" json:"ip"`
	RequestPath    string      `bson:"request_path" json:"request_path"`
	Reason         string      `bson:"reason" json:"reason"`
	Source         string      `bson:"source" json:"source"`
	Tags           []string    `bson:"tags" json:"tags"`
	Action         string      `bson:"action" json:"action"`
	Score          int         `bson:"score,omitempty" json:"score,omitempty"`
	MLConfidence   float64     `bson:"ml_confidence,omitempty" json:"ml_confidence,omitempty"`
	
	// Detailed Data
	Request        FullRequest `bson:"request" json:"request"`
	TriggerPayload string      `bson:"trigger_payload" json:"trigger_payload"`
}

var logCollection *mongo.Collection

// [NEW] Channel for Real-Time SSE Broadcasting
var broadcast = make(chan AttackLog, 100)

func Init(client *mongo.Client, dbName string) {
	logCollection = client.Database(dbName).Collection("logs")
}

// [NEW] Helper for main.go to access the channel
func GetBroadcastChannel() chan AttackLog {
	return broadcast
}

// [NEW] Helper to Fetch Historical Logs from DB
func GetRecentLogs(limit int64) ([]AttackLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Sort by Timestamp Descending (Newest first)
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(limit)

	cursor, err := logCollection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []AttackLog
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func LogAttack(ip, path, reason, action, source string, tags []string, score int, confidence float64, fullReq FullRequest, trigger string) {
	entry := AttackLog{
		Timestamp:      time.Now(),
		IP:             ip,
		RequestPath:    path,
		Reason:         reason,
		Source:         source,
		Tags:           tags,
		Action:         action,
		Score:          score,
		MLConfidence:   confidence,
		Request:        fullReq,
		TriggerPayload: trigger,
	}

	// 1. Save to DB (Async)
	go func() {
		_, err := logCollection.InsertOne(context.Background(), entry)
		if err != nil {
			log.Printf("Failed to log attack to DB: %v", err)
		}
	}()

	// 2. Broadcast to Live Dashboard (Non-blocking)
	select {
	case broadcast <- entry:
	default:
		// Drop if channel full to prevent blocking WAF
	}
}