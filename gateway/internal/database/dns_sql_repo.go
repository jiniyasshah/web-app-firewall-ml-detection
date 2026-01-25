package database

import (
	"fmt"
)

// CreateDNSZone creates the SOA and NS records for a domain in PowerDNS
func CreateDNSZone(domainName string, nameservers []string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	// 1. Insert Domain
	result, err := dnsDB.Exec("INSERT INTO domains (name, type) VALUES (?, 'NATIVE')", domainName)
	if err != nil {
		return fmt.Errorf("failed to insert domain into SQL: %v", err)
	}

	domainID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %v", err)
	}

	// 2. Insert SOA Record
	soaContent := fmt.Sprintf("%s hostmaster.%s 1 10800 3600 604800 3600",
		nameservers[0], domainName)
	
	_, err = dnsDB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, disabled, change_date, created_at)
		VALUES (?, ?, 'SOA', ?, 3600, 0, UNIX_TIMESTAMP(), NOW())
	`, domainID, domainName, soaContent)
	if err != nil {
		return fmt.Errorf("failed to create SOA record: %v", err)
	}

	// 3. Insert NS Records
	for _, ns := range nameservers {
		_, err = dnsDB.Exec(`
			INSERT INTO records (domain_id, name, type, content, ttl, disabled, change_date, created_at)
			VALUES (?, ?, 'NS', ?, 3600, 0, UNIX_TIMESTAMP(), NOW())
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
	_, err := dnsDB.Exec("DELETE FROM domains WHERE name = ?", domainName)
	return err
}

// AddPowerDNSRecord inserts a new record with the correct IP (Real or WAF)
func AddPowerDNSRecord(name, rType, content string, proxied bool, wafIP string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	// Find Domain ID by matching the suffix
	var domainID int64
	row := dnsDB.QueryRow("SELECT id FROM domains WHERE ? LIKE CONCAT('%%', name) ORDER BY LENGTH(name) DESC LIMIT 1", name)
	if err := row.Scan(&domainID); err != nil {
		return fmt.Errorf("domain not found in SQL for record %s: %v", name, err)
	}

	finalContent := content
	if proxied && (rType == "A" || rType == "AAAA") {
		finalContent = wafIP
	}

	_, err := dnsDB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, change_date, created_at) 
		VALUES (?, ?, ?, ?, 300, 0, 0, UNIX_TIMESTAMP(), NOW())`, 
		domainID, name, rType, finalContent)
	
	return err
}

// DeletePowerDNSRecordByContent removes a specific record
func DeletePowerDNSRecordByContent(name, rType, content string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}
	_, err := dnsDB.Exec("DELETE FROM records WHERE name=? AND type=? AND content=?", name, rType, content)
	return err
}