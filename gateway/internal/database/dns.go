package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Package-level variable for MySQL connection
var dnsDB *sql.DB

// ConnectDNS establishes connection to PowerDNS MySQL database with retries
func ConnectDNS(user, pass, host, dbName string) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, dbName)

	var db *sql.DB
	var err error

	// Retry logic: Try 10 times, waiting 2 seconds between attempts
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("mysql", dsn)
		if err == nil {
			err = db.Ping()
			if err == nil {
				// Success!
				fmt.Println("✅ Connected to DNS SQL Database")
				dnsDB = db
				return nil
			}
		}

		fmt.Printf("⚠️  DNS DB unavailable (Attempt %d/%d): %v. Retrying in 2s...\n", i+1, maxRetries, err)
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("failed to connect to DNS DB after %d attempts: %v", maxRetries, err)
}

// CloseDNS closes the MySQL connection
func CloseDNS() {
	if dnsDB != nil {
		dnsDB.Close()
	}
}

// AddPowerDNSRecord inserts a new DNS record into PowerDNS (Resolution Backend)
// CRITICAL FIX: If 'proxied' is true, we ALWAYS create an 'A' record pointing to WAF IP,
// regardless of whether the user gave us a CNAME or A record.
// AddPowerDNSRecord inserts a new DNS record into PowerDNS
func AddPowerDNSRecord(name, recordType, content string, proxied bool, wafIP string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	// First, get the domain_id for the zone
	var domainID int
	zoneName := extractZone(name)

	err := dnsDB.QueryRow("SELECT id FROM domains WHERE name = ?", zoneName).Scan(&domainID)
	if err != nil {
		return fmt.Errorf("zone not found: %s (error: %v)", zoneName, err)
	}

	// --- LOGIC FOR PROXYING ---
	// 1. Determine if we SHOULD proxy.
	// We generally respect the user's choice ('proxied'), BUT we force it to FALSE
	// for "meta" records like TXT, MX, NS, SOA. These must be publicly visible
	// for verification (e.g. _vercel-verify, google-site-verification).
	shouldProxy := proxied
	if recordType == "TXT" || recordType == "MX" || recordType == "NS" || recordType == "SOA" {
		shouldProxy = false
	}

	// 2. Prepare the final data for the Public DNS
	finalType := recordType
	finalContent := content

	// If proxying is enabled (and allowed for this type), we mask the real destination
	// by publishing an 'A' record pointing to our WAF IP.
	if shouldProxy {
		finalType = "A"
		finalContent = wafIP
	}

	// Insert the record
	_, err = dnsDB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, disabled)
		VALUES (?, ?, ?, ?, 300, 0)
	`, domainID, name, finalType, finalContent)

	return err
}

// GetPowerDNSRecords fetches all DNS records for a domain from PowerDNS
func GetPowerDNSRecords(domainName string) ([]map[string]interface{}, error) {
	if dnsDB == nil {
		return nil, fmt.Errorf("DNS database not connected")
	}

	query := `
		SELECT r.id, r.name, r.type, r.content, r.ttl
		FROM records r
		JOIN domains d ON r.domain_id = d.id
		WHERE d.name = ?  OR r.name LIKE ?
	`

	rows, err := dnsDB.Query(query, domainName, "%."+domainName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []map[string]interface{}
	for rows.Next() {
		var id int
		var name, recordType, content string
		var ttl int

		if err := rows.Scan(&id, &name, &recordType, &content, &ttl); err != nil {
			continue
		}

		records = append(records, map[string]interface{}{
			"id":      id,
			"name":    name,
			"type":    recordType,
			"content": content,
			"ttl":     ttl,
		})
	}

	return records, nil
}

// DeletePowerDNSRecordByContent removes a record matching name, type, and content.
func DeletePowerDNSRecordByContent(name, recordType, content string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	_, err := dnsDB.Exec(`
		DELETE FROM records 
		WHERE name = ? AND type = ? AND content = ?
	`, name, recordType, content)
	
	return err
}

// Helper function to extract zone from full record
func extractZone(recordName string) string {
	parts := splitDomain(recordName)
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return recordName
}

func splitDomain(domain string) []string {
	var parts []string
	current := ""
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// CreateDNSZone creates a new zone in PowerDNS
func CreateDNSZone(domainName string, nameservers []string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	var existingID int
	err := dnsDB.QueryRow("SELECT id FROM domains WHERE name = ?", domainName).Scan(&existingID)
	if err == nil {
		return nil
	}

	result, err := dnsDB.Exec(`
		INSERT INTO domains (name, type) VALUES (?, 'NATIVE')
	`, domainName)
	if err != nil {
		return fmt.Errorf("failed to create zone: %v", err)
	}

	domainID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %v", err)
	}

	soaContent := fmt.Sprintf("%s hostmaster.%s 1 10800 3600 604800 3600",
		nameservers[0], domainName)
	
	_, err = dnsDB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, disabled)
		VALUES (?, ?, 'SOA', ?, 3600, 0)
	`, domainID, domainName, soaContent)
	if err != nil {
		return fmt.Errorf("failed to create SOA record: %v", err)
	}

	for _, ns := range nameservers {
		_, err = dnsDB.Exec(`
			INSERT INTO records (domain_id, name, type, content, ttl, disabled)
			VALUES (?, ?, 'NS', ?, 3600, 0)
		`, domainID, domainName, ns)
		if err != nil {
			return fmt.Errorf("failed to create NS record: %v", err)
		}
	}

	return nil
}

// DeleteDNSZone removes a zone and all its records from PowerDNS
func DeleteDNSZone(domainName string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	var domainID int
	err := dnsDB.QueryRow("SELECT id FROM domains WHERE name = ?", domainName).Scan(&domainID)
	if err != nil {
		return fmt.Errorf("zone not found: %v", err)
	}

	_, err = dnsDB.Exec("DELETE FROM records WHERE domain_id = ?", domainID)
	if err != nil {
		return fmt.Errorf("failed to delete records:  %v", err)
	}

	_, err = dnsDB.Exec("DELETE FROM domains WHERE id = ?", domainID)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %v", err)
	}

	return nil
}