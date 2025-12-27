package database

import (
	"context"
	"errors"
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

func CreateUser(client *mongo.Client, user detector.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Check if email exists
	var existing detector.User
	err := client.Database("waf").Collection("users").FindOne(ctx, bson.M{"email": user.Email}).Decode(&existing)
	if err == nil {
		return errors.New("email already registered")
	}

	user.ID = primitive.NewObjectID().Hex()
	_, err = client.Database("waf").Collection("users").InsertOne(ctx, user)
	return err
}

func GetUserByEmail(client *mongo.Client, email string) (*detector.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user detector.User
	err := client.Database("waf").Collection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil { return nil, err }
	return &user, nil
}

// --- DOMAIN MANAGEMENT ---

func CreateDomain(client *mongo.Client, domain detector.Domain) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	domain.ID = primitive.NewObjectID().Hex()
	domain.CreatedAt = time.Now()
	_, err := client.Database("waf").Collection("domains").InsertOne(ctx, domain)
	return err
}

func GetDomainsByUser(client *mongo.Client, userID string) ([]detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	cursor, err := client.Database("waf").Collection("domains").Find(ctx, bson.M{"user_id": userID})
	if err != nil { return nil, err }
	
	var domains []detector.Domain
	cursor.All(ctx, &domains)
	return domains, nil
}

// Find the domain config based on the incoming Host header (e.g., "example.com")
func GetDomainByName(client *mongo.Client, host string) (*detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // Fast timeout
	defer cancel()

	var domain detector.Domain
	err := client.Database("waf").Collection("domains").FindOne(ctx, bson.M{"name": host}).Decode(&domain)
	if err != nil { return nil, err }
	return &domain, nil
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

// [NEW] Helper to check domain ownership
func GetDomainByID(client *mongo.Client, id string) (*detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var domain detector.Domain
	// Note: _id in Mongo is usually an ObjectID or string depending on how you stored it. 
	// Since we stored it as a Hex string in CreateDomain, we query by "_id".
	err := client.Database("waf").Collection("domains").FindOne(ctx, bson.M{"_id": id}).Decode(&domain)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

// Fetch ALL rules (Enabled + Disabled) for a specific Domain so the Dashboard can manage them
func GetAllRules(client *mongo.Client, domainID string) ([]detector.WAFRule, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    var filter bson.M

    // LOGIC FIX:
    if domainID == "" {
        // Case 1: Fetching Global Rules
        // We look for documents where "domain_id" does NOT exist
        filter = bson.M{"domain_id": bson.M{"$exists": false}}
    } else {
        // Case 2: Fetching Specific Domain Rules
        // We look ONLY for that domain. We do NOT use $or here, 
        // because the Handler already merges the lists for us.
        filter = bson.M{"domain_id": domainID}
    }

    cursor, err := client.Database("waf").Collection("rules").Find(ctx, filter)
    if err != nil {
        return nil, err
    }
    defer cursor.Close(ctx)

    var rules []detector.WAFRule
    if err = cursor.All(ctx, &rules); err != nil {
        return nil, err
    }
    
    // Safety check: ensure we return an empty slice instead of nil if no rules found
    if rules == nil {
        rules = []detector.WAFRule{}
    }

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

// GetLogsForUser (Secured View - Only logs for domains owned by user)
func GetLogsForUser(client *mongo.Client, userID string, limit int64) ([]interface{}, error) {
	// 1. Get all domain IDs for this user
	domains, err := GetDomainsByUser(client, userID)
	if err != nil {
		return nil, err
	}

	domainIDs := []string{}
	for _, d := range domains {
		domainIDs = append(domainIDs, d.ID)
	}

	// If user has no domains, return empty list
	if len(domainIDs) == 0 {
		return []interface{}{}, nil
	}

	// 2. Fetch logs matching those domain IDs
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Note: You need to make sure your logs are saved with 'domain_id'.
	// If not, you might need to filter by 'request.headers.Host' or similar.
	// For now, assuming logs have 'domain_id' or we filter roughly by IP/Host if added.
	// This query assumes you update logger.go to save DomainID.
	// If you haven't yet, you might need to query by "request.url" regex matching the domain names.
	
	// Fallback Strategy: Match Host Header in logs corresponding to user domains
	// (Since we didn't add DomainID to the Log struct in previous steps)
	domainNames := []string{}
	for _, d := range domains {
		domainNames = append(domainNames, d.Name)
	}

	// Filter logs where Host header matches one of the user's domains
	// Note: This requires the log structure to have headers accessible in query
	// Ideally, add "domain_id" to AttackLog struct in logger.go for performance.
	filter := bson.M{
		"request.headers.Host": bson.M{"$in": domainNames}, // Go driver handles []string mapping to Headers map
	}
	
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(limit)

	cursor, err := client.Database("waf").Collection("logs").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []interface{}
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, err
	}

	return logs, nil
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