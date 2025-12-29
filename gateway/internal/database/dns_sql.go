package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var DNSDB *sql.DB

func ConnectDNS(user, password, host, dbName string) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", user, password, host, dbName)
	var err error
	DNSDB, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	
	// Keep trying to connect until the DB is ready (Container startup race condition)
	for i := 0; i < 10; i++ {
		err = DNSDB.Ping()
		if err == nil {
			log.Println("Connected to DNS Database (MySQL)!")
			return nil
		}
		log.Printf("Waiting for DNS DB... (%v)\n", err)
		time.Sleep(2 * time.Second)
	}
	return err
}

// AddRecord handles the "Split Horizon" logic
// If proxied=true: Public DNS gets WAF IP, but we store Origin IP for internal routing
// If proxied=false: Public DNS gets Real IP (Bypass WAF)
func AddDNSRecord(domainName, recordType, content string, proxied bool, wafIP string) error {
	if DNSDB == nil {
		return fmt.Errorf("DNS DB not connected")
	}

	// 1. Get Domain ID
	var domainID int
	err := DNSDB.QueryRow("SELECT id FROM domains WHERE name = ?", domainName).Scan(&domainID)
	if err == sql.ErrNoRows {
		// Auto-create domain zone if missing
		res, _ := DNSDB.Exec("INSERT INTO domains (name, type) VALUES (?, 'NATIVE')", domainName)
		id, _ := res.LastInsertId()
		domainID = int(id)
	}

	// 2. Determine what to show the world
	publicContent := content
	if proxied && recordType == "A" {
		publicContent = wafIP // The World sees YOU
	}

	// 3. Insert/Update Public DNS Record
	// We delete old ones for simplicity in this demo (Limit 1 A record per domain)
	_, err = DNSDB.Exec("DELETE FROM records WHERE name=? AND type=?", domainName, recordType)
	if err != nil { return err }

	_, err = DNSDB.Exec(`
		INSERT INTO records (domain_id, name, content, type, ttl, prio) 
		VALUES (?, ?, ?, ?, 300, 0)`, 
		domainID, domainName, publicContent, recordType)
	
	return err
}