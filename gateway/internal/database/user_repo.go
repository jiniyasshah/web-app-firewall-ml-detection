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
		return errors.New("Email is already registered")
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

func UpdateUserPassword(client *mongo.Client, userID string, hashedPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	_, err := client.Database(DBName).Collection("users").UpdateOne(ctx, 
		bson.M{"_id": userID}, 
		bson.M{
			"$set": bson.M{"password": hashedPassword},
			"$inc": bson.M{"token_version": 1}, // [NEW] Invalidates all old tokens!
		},
	)
	return err
}

func SetPasswordResetToken(client *mongo.Client, email string, token string, expiry int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	result, err := client.Database(DBName).Collection("users").UpdateOne(ctx, 
		bson.M{"email": email}, 
		bson.M{"$set": bson.M{"reset_token": token, "reset_token_expiry": expiry}},
	)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}
	return nil
}

func GetUserByResetToken(client *mongo.Client, token string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	
	var user models.User
	err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"reset_token": token}).Decode(&user)
	if err != nil {
		return nil, errors.New("invalid or expired token")
	}
	return &user, nil
}

func ClearPasswordResetToken(client *mongo.Client, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	_, err := client.Database(DBName).Collection("users").UpdateOne(ctx, 
		bson.M{"_id": userID}, 
		bson.M{"$unset": bson.M{"reset_token": "", "reset_token_expiry": ""}},
	)
	return err
}

func SetPendingEmail(client *mongo.Client, userID string, pendingEmail, token string, expiry int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	// Ensure the new email isn't already used by another fully registered user
	var existing models.User
	if err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"email": pendingEmail}).Decode(&existing); err == nil {
		return errors.New("this email is already in use by another account")
	}

	_, err := client.Database(DBName).Collection("users").UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{
			"pending_email":             pendingEmail,
			"email_change_token":        token,
			"email_change_token_expiry": expiry,
		}},
	)
	return err
}

func GetUserByEmailChangeToken(client *mongo.Client, token string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	var user models.User
	err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"email_change_token": token}).Decode(&user)
	if err != nil {
		return nil, errors.New("invalid or expired verification link")
	}
	return &user, nil
}

func ConfirmEmailChange(client *mongo.Client, userID, newEmail string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	_, err := client.Database(DBName).Collection("users").UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{"email": newEmail},
			"$unset": bson.M{
				"pending_email":             "",
				"email_change_token":        "",
				"email_change_token_expiry": "",
			},
		},
	)
	return err
}

