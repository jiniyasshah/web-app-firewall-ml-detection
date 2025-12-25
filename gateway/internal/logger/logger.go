package logger

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type FullRequest struct {
	Method  string              `bson:"method"`
	URL     string              `bson:"url"`
	Headers map[string][]string `bson:"headers"`
	Body    string              `bson:"body"`
}

type AttackLog struct {
	Timestamp      time.Time   `bson:"timestamp"`
	IP             string      `bson:"ip"`
	RequestPath    string      `bson:"request_path"`
	Reason         string      `bson:"reason"`
	Source         string      `bson:"source"`
	Tags           []string    `bson:"tags"`
	Action         string      `bson:"action"`
	Score          int         `bson:"score,omitempty"`
	MLConfidence   float64     `bson:"ml_confidence,omitempty"`
	
	// [NEW] Detailed Data
	Request        FullRequest `bson:"request"`         // The entire HTTP request
	TriggerPayload string      `bson:"trigger_payload"` // The specific snippet that triggered the block
}

var logCollection *mongo.Collection

func Init(client *mongo.Client, dbName string) {
	logCollection = client.Database(dbName).Collection("logs")
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

	go func() {
		_, err := logCollection.InsertOne(context.Background(), entry)
		if err != nil {
			log.Printf("Failed to log attack to DB: %v", err)
		}
	}()
}