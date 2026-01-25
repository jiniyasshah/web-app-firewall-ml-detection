package database

import (
	"context"
	"time"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func CreateDNSRecord(client *mongo.Client, record models.DNSRecord) (string, error) {
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
	filter := bson.M{"domain_id": domainID, "name": name, "type": rType, "content": content}
	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, filter).Err()
	if err == mongo.ErrNoDocuments { return false, nil }
	if err != nil { return false, err }
	return true, nil
}

func CheckDNSRecordExists(client *mongo.Client, domainID, name, rType string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	filter := bson.M{"domain_id": domainID, "name": name, "type": rType}
	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, filter).Err()
	if err == mongo.ErrNoDocuments { return false, nil }
	if err != nil { return false, err }
	return true, nil
}

func GetDNSRecords(client *mongo.Client, domainID string) ([]models.DNSRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	cursor, err := client.Database(DBName).Collection("dns_records").Find(ctx, bson.M{"domain_id": domainID})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var records []models.DNSRecord
	if err = cursor.All(ctx, &records); err != nil { return nil, err }
	if records == nil { records = []models.DNSRecord{} }
	return records, nil
}

func GetDNSRecordByID(client *mongo.Client, recordID string) (*models.DNSRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	var record models.DNSRecord
	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, bson.M{"_id": recordID}).Decode(&record)
	if err != nil { return nil, err }
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
	_, err := client.Database(DBName).Collection("dns_records").UpdateOne(ctx, 
		bson.M{"_id": recordID}, 
		bson.M{"$set": bson.M{"proxied": proxied}})
	return err
}

func UpdateDNSRecordOriginSSL(client *mongo.Client, recordID string, sslStatus bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Database(DBName).Collection("dns_records").UpdateOne(ctx, 
		bson.M{"_id": recordID}, 
		bson.M{"$set": bson.M{"origin_ssl": sslStatus}})
	return err
}

func GetOriginRecord(client *mongo.Client, host string) (*models.DNSRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var record models.DNSRecord

	// 1. Try A
	err := client.Database(DBName).Collection("dns_records").FindOne(ctx, bson.M{"name": host, "type": "A"}).Decode(&record)
	if err == nil { return &record, nil }

	// 2. Try CNAME
	err = client.Database(DBName).Collection("dns_records").FindOne(ctx, bson.M{"name": host, "type": "CNAME"}).Decode(&record)
	if err == nil { return &record, nil }

	return nil, err
}

func GetAllDNSRecords(client *mongo.Client) ([]models.DNSRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cursor, err := client.Database(DBName).Collection("dns_records").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var records []models.DNSRecord
	if err = cursor.All(ctx, &records); err != nil { return nil, err }
	return records, nil
}

func DeleteDNSRecordsByDomainID(client *mongo.Client, domainID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), TimeoutDuration)
	defer cancel()
	_, err := client.Database(DBName).Collection("dns_records").DeleteMany(ctx, bson.M{"domain_id": domainID})
	return err
}