// type: uploaded file
// fileName: jiniyasshah/web-app-firewall-ml-detection/web-app-firewall-ml-detection-test/gateway/internal/logger/logger.go
package logger

import (
	"context"
	"log"
	"time"

	"web-app-firewall-ml-detection/internal/detector" // Imported and USED now

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// [DELETED] FullRequest and AttackLog structs are removed from here.
// They are now imported from "web-app-firewall-ml-detection/internal/detector"

var logCollection *mongo.Collection

// [UPDATED] Use detector.AttackLog
var broadcast = make(chan detector.AttackLog, 100)

func Init(client *mongo.Client, dbName string) {
	logCollection = client.Database(dbName).Collection("logs")
}

// [UPDATED] Use detector.AttackLog
func GetBroadcastChannel() chan detector.AttackLog {
	return broadcast
}

// [UPDATED] Use detector.AttackLog
func GetRecentLogs(limit int64) ([]detector.AttackLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(limit)

	cursor, err := logCollection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []detector.AttackLog
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

// [UPDATED] Use detector.FullRequest and detector.AttackLog
func LogAttack(userID, domainID, ip, path, reason, action, source string, tags []string, score int, confidence float64, fullReq detector.FullRequest, trigger string) {
	entry := detector.AttackLog{
		UserID:         userID,
		DomainID:       domainID,
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

	// Run entire logging flow asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// 1. Save to DB first
		res, err := logCollection.InsertOne(ctx, entry)
		if err != nil {
			log.Printf("Failed to log attack to DB: %v", err)
		} else {
			// 2. Update with generated ID
			entry.ID = res.InsertedID
		}

		// 3. Broadcast
		select {
		case broadcast <- entry:
		default:
		}
	}()
}