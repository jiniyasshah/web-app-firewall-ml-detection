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

const (
	DBName          = "waf"
	TimeoutDuration = 5 * time.Second
)

// Connect initializes the MongoDB client
func Connect(uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	// Verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	return client, nil
}

// ---------------------------------------------------------
// USER MANAGEMENT
// ---------------------------------------------------------

func CreateUser(client *mongo.Client, user detector.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	// Check if email exists
	var existing detector.User
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

func GetUserByEmail(client *mongo.Client, email string) (*detector.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	var user detector.User
	err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByID(client *mongo.Client, id string) (*detector.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	var user detector.User
	err := client.Database(DBName).Collection("users").FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}


// ---------------------------------------------------------
// DOMAIN MANAGEMENT
// ---------------------------------------------------------

func CreateDomain(client *mongo.Client, domain detector.Domain) (detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	if domain.ID == "" {
		domain.ID = primitive.NewObjectID().Hex()
	}
	domain.CreatedAt = time.Now()

	_, err := client.Database(DBName).Collection("domains").InsertOne(ctx, domain)
	if err != nil {
		return detector.Domain{}, err
	}

	return domain, nil
}

func GetDomainsByUser(client *mongo.Client, userID string) ([]detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	cursor, err := client.Database(DBName).Collection("domains").Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var domains []detector.Domain
	if err = cursor.All(ctx, &domains); err != nil {
		return nil, err
	}
	return domains, nil
}

// GetDomainByName finds config based on Host header (e.g., "example.com")
func GetDomainByName(client *mongo.Client, host string) (*detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // Fast timeout for request path
	defer cancel()

	var domain detector.Domain
	err := client.Database(DBName).Collection("domains").FindOne(ctx, bson.M{"name": host}).Decode(&domain)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

func GetDomainByID(client *mongo.Client, id string) (*detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	var domain detector.Domain
	err := client.Database(DBName).Collection("domains").FindOne(ctx, bson.M{"_id": id}).Decode(&domain)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}


// ---------------------------------------------------------
// RULE MANAGEMENT
// ---------------------------------------------------------

// GetRules is the unified function to fetch rules based on a filter
func GetRules(client *mongo.Client, filter bson.M) ([]detector.WAFRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}) // Stable ordering
	cursor, err := client.Database(DBName).Collection("rules").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var rules []detector.WAFRule
	if err = cursor.All(ctx, &rules); err != nil {
		return nil, err
	}

	// Safety: return empty slice instead of nil
	if rules == nil {
		rules = []detector.WAFRule{}
	}

	return compileRegexes(rules), nil
}

func AddRule(client *mongo.Client, rule detector.WAFRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	if rule.ID == "" {
		rule.ID = primitive.NewObjectID().Hex()
	}
	_, err := client.Database(DBName).Collection("rules").InsertOne(ctx, rule)
	return err
}

func UpdateRule(client *mongo.Client, rule detector.WAFRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	filter := bson.M{"_id": rule.ID}
	update := bson.M{"$set": rule}
	_, err := client.Database(DBName).Collection("rules").UpdateOne(ctx, filter, update)
	return err
}

func DeleteRule(client *mongo.Client, ruleID, ownerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	// Safety: Only delete if the user owns it
	filter := bson.M{"_id": ruleID, "owner_id": ownerID}
	res, err := client.Database(DBName).Collection("rules").DeleteOne(ctx, filter)
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return errors.New("rule not found or unauthorized")
	}
	return nil
}

// ---------------------------------------------------------
// POLICY MANAGEMENT (Overrides)
// ---------------------------------------------------------

// GetPoliciesByUser fetches all policies (enabled/disabled states) for a specific user
func GetPoliciesByUser(client *mongo.Client, userID string) ([]detector.RulePolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	cursor, err := client.Database(DBName).Collection("rule_policies").Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var policies []detector.RulePolicy
	if err = cursor.All(ctx, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// UpsertRulePolicy handles enabling/disabling a rule for a user/domain
func UpsertRulePolicy(client *mongo.Client, policy detector.RulePolicy) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	filter := bson.M{
		"user_id":   policy.UserID,
		"rule_id":   policy.RuleID,
		"domain_id": policy.DomainID,
	}

	update := bson.M{"$set": bson.M{"enabled": policy.Enabled}}
	opts := options.Update().SetUpsert(true)

	_, err := client.Database(DBName).Collection("rule_policies").UpdateOne(ctx, filter, update, opts)
	return err
}

// ---------------------------------------------------------
// LOGGING
// ---------------------------------------------------------

func GetLogsForUser(client *mongo.Client, userID string, limit int64) ([]interface{}, error) {
	// 1.Get all domain IDs for this user
	domains, err := GetDomainsByUser(client, userID)
	if err != nil {
		return nil, err
	}

	if len(domains) == 0 {
		return []interface{}{}, nil
	}

	// 2.Filter logs by Host Header matching user's domains
	// Note: In a production V2, we should store 'domain_id' directly in the logs collection for efficiency.
	domainNames := make([]string, len(domains))
	for i, d := range domains {
		domainNames[i] = d.Name
	}

	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	filter := bson.M{
		"request.headers.Host": bson.M{"$in": domainNames},
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(limit)

	cursor, err := client.Database(DBName).Collection("logs").Find(ctx, filter, opts)
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

// --- GLOBAL FETCH HELPERS (For API Cache Reload) ---

// GetAllDomains fetches every domain in the system to build the routing map
func GetAllDomains(client *mongo.Client) ([]detector.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	cursor, err := client.Database(DBName).Collection("domains").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)

	var domains []detector.Domain
	if err = cursor.All(ctx, &domains); err != nil { return nil, err }
	return domains, nil
}

// GetAllPolicies fetches every policy to determine rule enablement
func GetAllPolicies(client *mongo.Client) ([]detector.RulePolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	cursor, err := client.Database(DBName).Collection("rule_policies").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)

	var policies []detector.RulePolicy
	if err = cursor.All(ctx, &policies); err != nil { return nil, err }
	return policies, nil
}

// UpdateDomainTarget saves the REAL Origin IP for the WAF to use
func UpdateDomainRouting(client *mongo.Client, domainName string, originIP string, proxied bool) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    collection := client.Database("waf").Collection("domains")
    filter := bson.M{"name": domainName}
    
    update := bson.M{
        "$set": bson.M{
            "target_ip": originIP, // The Secret Real IP
            "proxied":   proxied,
            "updated_at": time.Now(),
        },
    }
    _, err := collection.UpdateOne(ctx, filter, update)
    return err
}

// UpdateDomainStatus activates the domain after verification
func UpdateDomainStatus(client *mongo.Client, domainID, status string, proxied bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database("waf").Collection("domains")
	filter := bson.M{"_id": domainID}
	
	update := bson.M{
		"$set": bson.M{
			"status": status,
			"proxied": proxied,
			"updated_at": time.Now(),
		},
	}
	_, err := collection.UpdateOne(ctx, filter, update)
	return err
}




// ---------------------------------------------------------
// HELPERS
// ---------------------------------------------------------

// compileRegexes pre-compiles regex strings in rules to Go Regexp objects
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