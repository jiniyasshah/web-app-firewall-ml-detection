package database

import (
	"context"
	"log"
	"regexp"
	"time"
	"web-app-firewall-ml-detection/internal/detector"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Connect(uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil { return nil, err }
	return client, client.Ping(ctx, nil)
}

func LoadRules(client *mongo.Client, dbName, collName string) ([]detector.WAFRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database(dbName).Collection(collName)
	opts := options.Find().SetSort(bson.D{{Key: "priority", Value: -1}})
	cursor, err := collection.Find(ctx, bson.M{"enabled": true}, opts)
	if err != nil { return nil, err }
	defer cursor.Close(ctx)

	var rules []detector.WAFRule
	if err = cursor.All(ctx, &rules); err != nil { return nil, err }

	// OPTIMIZATION: Pre-compile Regexes
	for i := range rules {
		for j := range rules[i].Conditions {
			cond := &rules[i].Conditions[j]
			if cond.Operator == "regex" {
				if strVal, ok := cond.Value.(string); ok {
					// Compile once, use forever
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
	return rules, nil
}