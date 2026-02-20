package database

import (
	"context"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GetLogs(client *mongo.Client, domainID string, page, limit int, action, ip, source string) ([]models.AttackLog, int64, int64, int64, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	collection := client.Database(DBName).Collection("logs")

	baseFilter := bson.M{}
	if domainID != "" && domainID != "all" {
		baseFilter["domain_id"] = domainID
	}

	queryFilter := bson.M{}
	for k, v := range baseFilter {
		queryFilter[k] = v 
	}

	if action != "" && action != "All" {
		queryFilter["action"] = action
	}
	if ip != "" {
		// [FIXED] Changed "ip_address" to "ip" to match your MongoDB schema!
		queryFilter["ip"] = bson.M{"$regex": primitive.Regex{Pattern: ip, Options: "i"}}
	}
	
	// [UPDATED] Filter by Source instead of Attack Type
	if source != "" && source != "All" {
		queryFilter["source"] = source 
	}

	// ... rest of the function remains exactly the same ...
	totalEvents, _ := collection.CountDocuments(ctx, baseFilter)

	blockedFilter := bson.M{"action": "Blocked"}
	for k, v := range baseFilter { blockedFilter[k] = v }
	blockedCount, _ := collection.CountDocuments(ctx, blockedFilter)

	flaggedFilter := bson.M{"action": "Flagged"}
	for k, v := range baseFilter { flaggedFilter[k] = v }
	flaggedCount, _ := collection.CountDocuments(ctx, flaggedFilter)

	totalFiltered, err := collection.CountDocuments(ctx, queryFilter)
	if err != nil {
		return nil, 0, 0, 0, 0, err
	}

	findOptions := options.Find()
	findOptions.SetSort(bson.D{{Key: "timestamp", Value: -1}})
	findOptions.SetSkip(int64((page - 1) * limit))
	findOptions.SetLimit(int64(limit))

	cursor, err := collection.Find(ctx, queryFilter, findOptions)
	if err != nil {
		return nil, 0, 0, 0, 0, err
	}
	defer cursor.Close(ctx)

	var logs []models.AttackLog
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, 0, 0, 0, 0, err
	}
	if logs == nil {
		logs = []models.AttackLog{}
	}

	return logs, totalFiltered, totalEvents, blockedCount, flaggedCount, nil
}