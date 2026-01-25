package database

import (
	"context"
	"time"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func CreateDomain(client *mongo.Client, domain models.Domain) (models.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	if domain.ID == "" {
		domain.ID = primitive.NewObjectID().Hex()
	}
	domain.CreatedAt = time.Now()

	domain.Stats = models.DomainStats{
		TotalRequests:   0,
		FlaggedRequests: 0,
		BlockedRequests: 0,
	}

	_, err := client.Database(DBName).Collection("domains").InsertOne(ctx, domain)
	if err != nil {
		return models.Domain{}, err
	}
	return domain, nil
}

func GetDomainsByUser(client *mongo.Client, userID string) ([]models.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	cursor, err := client.Database(DBName).Collection("domains").Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var domains []models.Domain
	if err = cursor.All(ctx, &domains); err != nil {
		return nil, err
	}
	return domains, nil
}

func GetDomainByName(client *mongo.Client, host string) (*models.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var domain models.Domain
	filter := bson.M{"name": host, "status": "active"}
	err := client.Database(DBName).Collection("domains").FindOne(ctx, filter).Decode(&domain)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

func GetDomainByID(client *mongo.Client, id string) (*models.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	var domain models.Domain
	err := client.Database(DBName).Collection("domains").FindOne(ctx, bson.M{"_id": id}).Decode(&domain)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

func GetAllDomains(client *mongo.Client) ([]models.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	cursor, err := client.Database(DBName).Collection("domains").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var domains []models.Domain
	if err = cursor.All(ctx, &domains); err != nil { return nil, err }
	return domains, nil
}

func UpdateDomainStatus(client *mongo.Client, domainID, status string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Database(DBName).Collection("domains").UpdateOne(ctx, 
		bson.M{"_id": domainID}, 
		bson.M{"$set": bson.M{"status": status, "updated_at": time.Now()}})
	return err
}

func RevokeOldOwnership(client *mongo.Client, domainName string, newOwnerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{"name": domainName, "_id": bson.M{"$ne": newOwnerID}}
	_, err := client.Database(DBName).Collection("domains").DeleteMany(ctx, filter)
	return err
}

func IncrementDomainStats(client *mongo.Client, domainID string, total, flagged, blocked int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	update := bson.M{
		"$inc": bson.M{
			"stats.total_requests":   total,
			"stats.flagged_requests": flagged,
			"stats.blocked_requests": blocked,
		},
	}

	_, err := client.Database(DBName).Collection("domains").UpdateOne(ctx, bson.M{"_id": domainID}, update)
	return err
}

func DeleteDomain(client *mongo.Client, domainID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	_, err := client.Database(DBName).Collection("domains").DeleteOne(ctx, bson.M{"_id": domainID})
	return err
}