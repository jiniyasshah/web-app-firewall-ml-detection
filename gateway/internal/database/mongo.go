// type: uploaded file
// fileName: jiniyasshah/web-app-firewall-ml-detection/web-app-firewall-ml-detection-test/gateway/internal/database/mongo.go
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
// DNS RECORD MANAGEMENT (MongoDB - User View)
// ---------------------------------------------------------

type DNSRecord struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	DomainID  string    `bson:"domain_id" json:"domain_id"`
	Name      string    `bson:"name" json:"name"`
	Type      string    `bson:"type" json:"type"`
	Content   string    `bson:"content" json:"content"` // This is the ORIGIN IP (User View)
	TTL       int       `bson:"ttl" json:"ttl"`
	Proxied   bool      `bson:"proxied" json:"proxied"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

func CreateDNSRecord(client *mongo.Client, record DNSRecord) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	if record.ID == "" {
		record.ID = primitive.NewObjectID().Hex()
	}
	record.CreatedAt = time.Now()

	_, err := client.Database(DBName).Collection("dns_records").InsertOne(ctx, record)
	if err != nil {
		return "", err
	}
	return record.ID, nil
}

func CheckDuplicateDNSRecord(client *mongo.Client, domainID, name, rType, content string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	filter := bson.M{
		"domain_id": domainID,
		"name":      name,
		"type":      rType,
		"content":   content,
	}

	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, filter).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func CheckDNSRecordExists(client *mongo.Client, domainID, name, rType string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	filter := bson.M{
		"domain_id": domainID,
		"name":      name,
		"type":      rType,
	}

	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, filter).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func GetDNSRecords(client *mongo.Client, domainID string) ([]DNSRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	cursor, err := client.Database(DBName).Collection("dns_records").Find(ctx, bson.M{"domain_id": domainID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var records []DNSRecord
	if err = cursor.All(ctx, &records); err != nil {
		return nil, err
	}
	if records == nil {
		records = []DNSRecord{}
	}
	return records, nil
}

func GetDNSRecordByID(client *mongo.Client, recordID string) (*DNSRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	var record DNSRecord
	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, bson.M{"_id": recordID}).Decode(&record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func DeleteDNSRecord(client *mongo.Client, recordID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	_, err := client.Database(DBName).Collection("dns_records").DeleteOne(ctx, bson.M{"_id": recordID})
	return err
}

func UpdateDNSRecordProxy(client *mongo.Client, recordID string, proxied bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	collection := client.Database(DBName).Collection("dns_records")
	filter := bson.M{"_id": recordID}
	update := bson.M{"$set": bson.M{"proxied": proxied}}

	_, err := collection.UpdateOne(ctx, filter, update)
	return err
}

func GetOriginIP(client *mongo.Client, host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) 
	defer cancel()

	var record DNSRecord

	// 1. Try to find an exact 'A' record match first
	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, bson.M{
		"name": host,
		"type": "A",
	}).Decode(&record)

	if err == nil {
		return record.Content, nil
	}

	// 2. If no A record, try to find a 'CNAME' record
	err = client.Database(DBName).Collection("dns_records").FindOne(ctx, bson.M{
		"name": host,
		"type": "CNAME",
	}).Decode(&record)

	if err == nil {
		return record.Content, nil
	}

	return "", err
}

// ---------------------------------------------------------
// RULE MANAGEMENT
// ---------------------------------------------------------

func GetRules(client *mongo.Client, filter bson.M) ([]detector.WAFRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})
	cursor, err := client.Database(DBName).Collection("rules").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var rules []detector.WAFRule
	if err = cursor.All(ctx, &rules); err != nil {
		return nil, err
	}

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
// LOGGING - UPDATED FOR PAGINATION & DIRECT ID MATCHING
// ---------------------------------------------------------

// LogFilter defines options for fetching logs
type LogFilter struct {
	UserID   string
	DomainID string // Optional: Empty means all user's domains
	Page     int64
	Limit    int64
}

type PaginatedLogs struct {
	Data       []interface{} `json:"data"`
	Pagination struct {
		CurrentPage int64 `json:"current_page"`
		TotalPages  int64 `json:"total_pages"`
		TotalItems  int64 `json:"total_items"`
		PerPage     int64 `json:"per_page"`
	} `json:"pagination"`
}

// GetLogs fetches paginated logs for a user, using direct ID matching
func GetLogs(client *mongo.Client, filter LogFilter) (*PaginatedLogs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := client.Database(DBName).Collection("logs")
	mongoFilter := bson.M{}

	// 1. Build Query using IDs (New Schema)
	if filter.DomainID != "" {
		// Specific domain filter
		// Check ownership of domain first for security
		domain, err := GetDomainByID(client, filter.DomainID)
		if err != nil {
			return nil, err
		}
		if domain.UserID != filter.UserID {
			return nil, errors.New("unauthorized: domain does not belong to user")
		}
		
		// Query by domain_id field
		mongoFilter["domain_id"] = filter.DomainID
	} else {
		// All domains for this user
		mongoFilter["user_id"] = filter.UserID
	}

	// 2. Count Total Documents (for pagination)
	totalItems, err := collection.CountDocuments(ctx, mongoFilter)
	if err != nil {
		return nil, err
	}

	// 3. Calculate Pagination
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Limit < 1 {
		filter.Limit = 20
	}
	skip := (filter.Page - 1) * filter.Limit
	totalPages := int64(0)
	if filter.Limit > 0 {
		totalPages = (totalItems + filter.Limit - 1) / filter.Limit
	}

	// 4. Fetch Data
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}). // Newest first
		SetSkip(skip).
		SetLimit(filter.Limit)

	cursor, err := collection.Find(ctx, mongoFilter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []interface{}
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	if logs == nil {
		logs = []interface{}{}
	}

	// 5. Return Wrapper
	return &PaginatedLogs{
		Data: logs,
		Pagination: struct {
			CurrentPage int64 `json:"current_page"`
			TotalPages  int64 `json:"total_pages"`
			TotalItems  int64 `json:"total_items"`
			PerPage     int64 `json:"per_page"`
		}{
			CurrentPage: filter.Page,
			TotalPages:  totalPages,
			TotalItems:  totalItems,
			PerPage:     filter.Limit,
		},
	}, nil
}

// --- GLOBAL FETCH HELPERS (For API Cache Reload) ---

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

func UpdateDomainStatus(client *mongo.Client, domainID, status string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := client.Database("waf").Collection("domains")
	filter := bson.M{"_id": domainID}
	
	update := bson.M{
		"$set": bson.M{
			"status": status,
			"updated_at": time.Now(),
		},
	}
	_, err := collection.UpdateOne(ctx, filter, update)
	return err
}

// ---------------------------------------------------------
// HELPERS
// ---------------------------------------------------------

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

func IsHostAllowed(client *mongo.Client, host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var domain detector.Domain
	err := client.Database(DBName).Collection("domains").FindOne(ctx, bson.M{"name": host}).Decode(&domain)
	if err == nil {
		return true 
	}

	var record DNSRecord
	err = client.Database(DBName).Collection("dns_records").FindOne(ctx, bson.M{"name": host}).Decode(&record)
	if err == nil {
		return true 
	}

	return false
}