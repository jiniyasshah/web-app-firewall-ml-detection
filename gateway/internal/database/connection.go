package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	DBName          = "waf"
	TimeoutDuration = 5 * time.Second
)

// Shared SQL Connection
var dnsDB *sql.DB

// ConnectMongo initializes the MongoDB client
func Connect(uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	return client, nil
}

// ConnectDNS establishes connection to PowerDNS MySQL database
func ConnectDNS(user, pass, host, dbName string) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, dbName)

	var db *sql.DB
	var err error

	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("mysql", dsn)
		if err == nil {
			err = db.Ping()
			if err == nil {
				fmt.Println("✅ Connected to DNS SQL Database")
				dnsDB = db
				return nil
			}
		}
		fmt.Printf("⚠️  DNS DB unavailable (Attempt %d/%d): %v. Retrying...\n", i+1, maxRetries, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to connect to DNS DB: %v", err)
}