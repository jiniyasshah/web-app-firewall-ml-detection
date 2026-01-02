package database

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AddRoutingRecord stores the origin IP for proxied domains
func AddRoutingRecord(client *mongo.Client, domainID, recordName, originIP string) error {
	collection := client.Database(DBName).Collection("routing")

	ctx, cancel := context. WithTimeout(context. Background(), TimeoutDuration)
	defer cancel()

	// Upsert:  Update if exists, insert if not
	filter := bson.M{"record_name": recordName}
	update := bson.M{
		"$set": bson.M{
			"domain_id":   domainID,
			"record_name": recordName,
			"origin_ip":   originIP,
			"updated_at":   time.Now(),
		},
	}
	opts := options.Update().SetUpsert(true)

	_, err := collection.UpdateOne(ctx, filter, update, opts)
	return err
}

// GetRoutingByHost returns the origin IP for a given hostname
func GetRoutingByHost(client *mongo.Client, host string) (string, error) {
	collection := client.Database(DBName).Collection("routing")

	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	var result struct {
		OriginIP string `bson:"origin_ip"`
	}

	err := collection.FindOne(ctx, bson.M{"record_name": host}).Decode(&result)
	if err != nil {
		return "", err
	}

	return result. OriginIP, nil
}

// DeleteRoutingRecord removes a routing entry
func DeleteRoutingRecord(client *mongo. Client, recordName string) error {
	collection := client. Database(DBName).Collection("routing")

	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	_, err := collection.DeleteOne(ctx, bson.M{"record_name":  recordName})
	return err
}