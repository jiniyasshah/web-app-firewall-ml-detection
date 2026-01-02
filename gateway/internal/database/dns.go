package database

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

// Package-level variable for MySQL connection
var dnsDB *sql.DB

// ConnectDNS establishes connection to PowerDNS MySQL database
func ConnectDNS(user, pass, host, dbName string) error {
	dsn := fmt. Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, dbName)

	db, err := sql. Open("mysql", dsn)
	if err != nil {
		return err
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return err
	}

	dnsDB = db
	return nil
}

// CloseDNS closes the MySQL connection
func CloseDNS() {
	if dnsDB != nil {
		dnsDB. Close()
	}
}

// AddDNSRecord inserts a new DNS record into PowerDNS
func AddDNSRecord(name, recordType, content string, proxied bool, wafIP string) error {
	// Check if database is connected
	if dnsDB == nil {
		return fmt. Errorf("DNS database not connected")
	}

	// First, get the domain_id for the zone
	var domainID int

	// Extract zone from record name (e.g., "www.  example.com" -> "example.com")
	zoneName := extractZone(name)

	err := dnsDB. QueryRow("SELECT id FROM domains WHERE name = ?", zoneName).Scan(&domainID)
	if err != nil {
		return fmt. Errorf("zone not found: %s (error: %v)", zoneName, err)
	}

	// If proxied, point to WAF IP; otherwise, point to user's content
	actualContent := content
	if proxied && recordType == "A" {
		actualContent = wafIP
	}

	// Insert the record
	_, err = dnsDB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, disabled)
		VALUES (?, ?, ?, ?, 300, 0)
	`, domainID, name, recordType, actualContent)

	return err
}

// GetDNSRecordsByDomain fetches all DNS records for a domain from PowerDNS
func GetDNSRecordsByDomain(domainName string) ([]map[string]interface{}, error) {
	if dnsDB == nil {
		return nil, fmt.Errorf("DNS database not connected")
	}

	query := `
		SELECT r.id, r. name, r.type, r.content, r.ttl
		FROM records r
		JOIN domains d ON r. domain_id = d.id
		WHERE d.name = ?  OR r.name LIKE ?
	`

	rows, err := dnsDB. Query(query, domainName, "%. "+domainName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []map[string]interface{}
	for rows.Next() {
		var id int
		var name, recordType, content string
		var ttl int

		if err := rows. Scan(&id, &name, &recordType, &content, &ttl); err != nil {
			continue
		}

		records = append(records, map[string]interface{}{
			"id":      id,
			"name":    name,
			"type":     recordType,
			"content": content,
			"ttl":     ttl,
		})
	}

	return records, nil
}

// DeleteDNSRecord removes a record from PowerDNS by ID
func DeleteDNSRecord(recordID string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	_, err := dnsDB.Exec("DELETE FROM records WHERE id = ?", recordID)
	return err
}
// Helper function to extract zone from full record name
func extractZone(recordName string) string {
	// Simple implementation:  find the last two parts
	// "www.api.example.com" -> "example.com"
	// "example.com" -> "example.com"
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

	// Check if zone already exists
	var existingID int
	err := dnsDB.QueryRow("SELECT id FROM domains WHERE name = ?", domainName).Scan(&existingID)
	if err == nil {
		// Zone already exists, that's fine
		return nil
	}

	// Create the zone
	result, err := dnsDB.Exec(`
		INSERT INTO domains (name, type) VALUES (?, 'NATIVE')
	`, domainName)
	if err != nil {
		return fmt.Errorf("failed to create zone: %v", err)
	}

	domainID, err := result.LastInsertId()
	if err != nil {
		return fmt. Errorf("failed to get zone ID: %v", err)
	}

	// Add SOA record (required for every zone)
	soaContent := fmt.Sprintf("%s. hostmaster.%s.  1 10800 3600 604800 3600",
		nameservers[0], domainName)
	
	_, err = dnsDB. Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, disabled)
		VALUES (?, ?, 'SOA', ?, 3600, 0)
	`, domainID, domainName, soaContent)
	if err != nil {
		return fmt. Errorf("failed to create SOA record: %v", err)
	}

	// Add NS records
	for _, ns := range nameservers {
		_, err = dnsDB. Exec(`
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

	// Get domain ID
	var domainID int
	err := dnsDB.QueryRow("SELECT id FROM domains WHERE name = ?", domainName).Scan(&domainID)
	if err != nil {
		return fmt.Errorf("zone not found: %v", err)
	}

	// Delete all records for this zone
	_, err = dnsDB.Exec("DELETE FROM records WHERE domain_id = ?", domainID)
	if err != nil {
		return fmt.Errorf("failed to delete records:  %v", err)
	}

	// Delete the zone
	_, err = dnsDB.Exec("DELETE FROM domains WHERE id = ?", domainID)
	if err != nil {
		return fmt. Errorf("failed to delete zone: %v", err)
	}

	return nil
}