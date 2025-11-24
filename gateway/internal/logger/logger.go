package logger

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type AttackLog struct {
	Timestamp    time.Time `bson:"timestamp"`
	IP           string    `bson:"ip"`
	RequestPath  string    `bson:"request_path"`
	AttackType   string    `bson:"attack_type"` // "Rule" or "ML"
	Score        int       `bson:"score,omitempty"`
	MLConfidence float64   `bson:"ml_confidence,omitempty"`
	Action       string    `bson:"action"` // "Blocked" or "Flagged"
}

var logCollection *mongo.Collection

func Init(client *mongo.Client, dbName string) {
	logCollection = client.Database(dbName).Collection("logs")
}

func LogAttack(ip, path, attackType, action string, score int, confidence float64) {
	entry := AttackLog{
		Timestamp:    time.Now(),
		IP:           ip,
		RequestPath:  path,
		AttackType:   attackType,
		Score:        score,
		MLConfidence: confidence,
		Action:       action,
	}

	// Run in background so we don't slow down the WAF
	go func() {
		_, err := logCollection.InsertOne(context.Background(), entry)
		if err != nil {
			log.Printf("Failed to log attack to DB: %v", err)
		}
	}()
}