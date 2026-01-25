package database

import (
	"context"
	"errors"
	"log"
	"regexp"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GetRules(client *mongo.Client, filter bson.M) ([]models.WAFRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})
	cursor, err := client.Database(DBName).Collection("rules").Find(ctx, filter, opts)
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var rules []models.WAFRule
	if err = cursor.All(ctx, &rules); err != nil { return nil, err }
	if rules == nil { rules = []models.WAFRule{} }
	return compileRegexes(rules), nil
}

func AddRule(client *mongo.Client, rule models.WAFRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	_, err := client.Database(DBName).Collection("rules").InsertOne(ctx, rule)
	return err
}

func DeleteRule(client *mongo.Client, ruleID, ownerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	objID, err := primitive.ObjectIDFromHex(ruleID)
	if err != nil {
		return errors.New("invalid rule ID format")
	}

	filter := bson.M{"_id": objID, "owner_id": ownerID}
	res, err := client.Database(DBName).Collection("rules").DeleteOne(ctx, filter)
	if err != nil { return err }
	if res.DeletedCount == 0 { return errors.New("rule not found or unauthorized") }
	return nil
}

func GetAllPolicies(client *mongo.Client) ([]models.RulePolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	cursor, err := client.Database(DBName).Collection("rule_policies").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var policies []models.RulePolicy
	if err = cursor.All(ctx, &policies); err != nil { return nil, err }
	return policies, nil
}

func GetPoliciesByUser(client *mongo.Client, userID string) ([]models.RulePolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	cursor, err := client.Database(DBName).Collection("rule_policies").Find(ctx, bson.M{"user_id": userID})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var policies []models.RulePolicy
	if err = cursor.All(ctx, &policies); err != nil { return nil, err }
	return policies, nil
}

func GetPoliciesByUserAndDomain(client *mongo.Client, userID, domainID string) ([]models.RulePolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	
	filter := bson.M{"user_id": userID}
	
	if domainID != "" {
		filter["domain_id"] = domainID
	} else {
		filter["domain_id"] = ""
	}

	cursor, err := client.Database(DBName).Collection("rule_policies").Find(ctx, filter)
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	
	var policies []models.RulePolicy
	if err = cursor.All(ctx, &policies); err != nil { return nil, err }
	return policies, nil
}

func UpsertRulePolicy(client *mongo.Client, policy models.RulePolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	filter := bson.M{"user_id": policy.UserID, "rule_id": policy.RuleID, "domain_id": policy.DomainID}
	update := bson.M{"$set": bson.M{"enabled": policy.Enabled}}
	opts := options.Update().SetUpsert(true)
	_, err := client.Database(DBName).Collection("rule_policies").UpdateOne(ctx, filter, update, opts)
	return err
}

func compileRegexes(rules []models.WAFRule) []models.WAFRule {
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