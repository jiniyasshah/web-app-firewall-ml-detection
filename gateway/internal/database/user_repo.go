package database

import (
	"context"
	"errors"
	"time"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func CreateUser(client *mongo.Client, user models.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	var existing models.User
	err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"email": user.Email}).Decode(&existing)
	if err == nil {
		return errors.New("email already registered")
	}

	if user.ID == "" {
		user.ID = primitive.NewObjectID().Hex()
	}
	_, err = client.Database(DBName).Collection("users").InsertOne(ctx, user)
	return err
}

func GetUserByEmail(client *mongo.Client, email string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	var user models.User
	err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByID(client *mongo.Client, id string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	var user models.User
	err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func VerifyUserToken(client *mongo.Client, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"verification_token": token}
	update := bson.M{
		"$set": bson.M{
			"is_verified":        true,
			"verification_token": "", // Clear the token after use
		},
	}

	result, err := client.Database(DBName).Collection("users").UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("invalid or expired verification token")
	}

	return nil
}