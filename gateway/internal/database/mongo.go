package database

import (
	"context"
	"log"
	"regexp"
	"time"
	"web-app-firewall-ml-detection/internal/detector"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Connect(uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	return client, client.Ping(ctx, nil)
}

// LoadRules fetches ONLY enabled rules for the Detector Engine
func LoadRules(client *mongo.Client, dbName, collName string) ([]detector.WAFRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database(dbName).Collection(collName)
	// Sort by priority or ID
	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})
	
	// FILTER: Only fetch enabled rules
	cursor, err := collection.Find(ctx, bson.M{"enabled": true}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var rules []detector.WAFRule
	if err = cursor.All(ctx, &rules); err != nil {
		return nil, err
	}

	return compileRegexes(rules), nil
}

// GetAllRules fetches ALL rules (Enabled & Disabled) for the Dashboard
func GetAllRules(client *mongo.Client, dbName, collName string) ([]detector.WAFRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database(dbName).Collection(collName)
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)

	var rules []detector.WAFRule
	if err = cursor.All(ctx, &rules); err != nil { return nil, err }
	
	return rules, nil
}

func AddRule(client *mongo.Client, dbName, collName string, rule detector.WAFRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Ensure ID is generated if missing
	if rule.ID == "" {
		rule.ID = primitive.NewObjectID().Hex()
	}

	collection := client.Database(dbName).Collection(collName)
	_, err := collection.InsertOne(ctx, rule)
	return err
}

func UpdateRule(client *mongo.Client, dbName, collName string, rule detector.WAFRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database(dbName).Collection(collName)
	filter := bson.M{"_id": rule.ID}
	update := bson.M{"$set": rule}
	_, err := collection.UpdateOne(ctx, filter, update)
	return err
}

func ToggleRule(client *mongo.Client, dbName, collName, id string, enabled bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database(dbName).Collection(collName)
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{"enabled": enabled}}
	_, err := collection.UpdateOne(ctx, filter, update)
	return err
}

// Helper to compile regexes
func compileRegexes(rules []detector.WAFRule) []detector.WAFRule {
	for i := range rules {
		for j := range rules[i].Conditions {
			cond := &rules[i].Conditions[j]
			if cond.Operator == "regex" {
				if strVal, ok := cond.Value.(string); ok {
					re, err := regexp.Compile(strVal)
					if err == nil {
						cond.CompiledRegex = re
					} else {
						log.Printf("Error compiling regex for rule %s: %v", rules[i].ID, err)
					}
				}
			}
		}
	}
	return rules
}