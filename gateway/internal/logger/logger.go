// type: uploaded file
// fileName: jiniyasshah/web-app-firewall-ml-detection/web-app-firewall-ml-detection-test/gateway/internal/logger/logger.go
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
	ID             interface{} `bson:"_id,omitempty" json:"id"` // Added ID field
	UserID         string      `bson:"user_id" json:"user_id"`     // [NEW]
	DomainID       string      `bson:"domain_id" json:"domain_id"` // [NEW]
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

// Channel for Real-Time SSE Broadcasting
var broadcast = make(chan AttackLog, 100)

func Init(client *mongo.Client, dbName string) {
	logCollection = client.Database(dbName).Collection("logs")
}

func GetBroadcastChannel() chan AttackLog {
	return broadcast
}

func GetRecentLogs(limit int64) ([]AttackLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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

// [UPDATED] Signature now includes userID and domainID
func LogAttack(userID, domainID, ip, path, reason, action, source string, tags []string, score int, confidence float64, fullReq FullRequest, trigger string) {
	entry := AttackLog{
		UserID:         userID,   // [NEW]
		DomainID:       domainID, // [NEW]
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

	// 1.Save to DB (Async)
	go func() {
		_, err := logCollection.InsertOne(context.Background(), entry)
		if err != nil {
			log.Printf("Failed to log attack to DB: %v", err)
		}
	}()

	// 2.Broadcast to Live Dashboard
	select {
	case broadcast <- entry:
	default:
	}
}