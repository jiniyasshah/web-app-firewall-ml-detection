package service

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/mongo"
)

var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

type DNSService struct {
	Mongo *mongo.Client
	Cfg   *config.Config
}

func NewDNSService(client *mongo.Client, cfg *config.Config) *DNSService {
	return &DNSService{
		Mongo: client,
		Cfg:   cfg,
	}
}

func (s *DNSService) GetRecords(domainID, userID string) ([]models.DNSRecord, error) {
	domain, err := database.GetDomainByID(s.Mongo, domainID)
	if err != nil {
		return nil, err
	}
	if domain.UserID != userID {
		return nil, errors.New("unauthorized")
	}

	return database.GetDNSRecords(s.Mongo, domainID)
}

func (s *DNSService) AddRecord(req models.DNSRecord, userID string) (*models.DNSRecord, error) {
	// 1. Sanitize
	req.Name = strings.TrimSpace(req.Name)
	req.Content = strings.TrimSpace(req.Content)
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))

	// 2. Verify Ownership & Status
	domain, err := database.GetDomainByID(s.Mongo, req.DomainID)
	if err != nil {
		return nil, errors.New("domain not found")
	}
	if domain.UserID != userID {
		return nil, errors.New("unauthorized")
	}
	if domain.Status != "active" {
		return nil, errors.New("domain must be verified before adding records")
	}

	// 3. TTL Validation
	if req.TTL == 0 {
		req.TTL = 300
	}
	if req.TTL < 60 || req.TTL > 86400 {
		return nil, errors.New("TTL must be between 60 and 86400 seconds")
	}

	// 4. Content Validation
	if err := s.validateContent(req.Type, req.Content); err != nil {
		return nil, err
	}

	// 5. Build Full Record Name
	recordName := domain.Name
	if req.Name != "" && req.Name != "@" {
		if !domainRegex.MatchString(req.Name) {
			return nil, errors.New("record name contains invalid characters")
		}
		recordName = req.Name + "." + domain.Name
	}

	// 6. CNAME Logic Checks
	if req.Type == "CNAME" {
		if recordName == domain.Name {
			return nil, errors.New("root domain (@) cannot be a CNAME record")
		}
		target := strings.TrimSuffix(req.Content, ".")
		if target == recordName {
			return nil, errors.New("CNAME cannot point to itself")
		}
	}

	// 7. Conflict Checks (DB)
	if err := s.checkConflicts(req.DomainID, recordName, req.Type, req.Content); err != nil {
		return nil, err
	}

	// 8. Prepare for Storage
	newRecord := models.DNSRecord{
		DomainID: req.DomainID,
		Name:     recordName,
		Type:     req.Type,
		Content:  req.Content,
		TTL:      req.TTL,
		Proxied:  req.Proxied,
	}

	// 9. Save to Mongo
	id, err := database.CreateDNSRecord(s.Mongo, newRecord)
	if err != nil {
		return nil, err
	}
	newRecord.ID = id

	// 10. Save to PowerDNS
	err = database.AddPowerDNSRecord(recordName, req.Type, req.Content, req.Proxied, s.Cfg.WafPublicIP)
	if err != nil {
		return nil, fmt.Errorf("DNS Propagation Error: %v", err)
	}

	return &newRecord, nil
}

// [UPDATED] Uses models.DNSUpdateRequest instead of anonymous struct
func (s *DNSService) UpdateRecord(recordID, userID string, updateReq models.DNSUpdateRequest) (map[string]interface{}, error) {

	// 1. Fetch & Verify
	record, err := database.GetDNSRecordByID(s.Mongo, recordID)
	if err != nil {
		return nil, errors.New("record not found")
	}
	domain, err := database.GetDomainByID(s.Mongo, record.DomainID)
	if err != nil || domain.UserID != userID {
		return nil, errors.New("unauthorized")
	}

	// --- BRANCH 1: Origin SSL Update ---
	if updateReq.Action == "toggle_origin_ssl" {
		err := database.UpdateDNSRecordOriginSSL(s.Mongo, recordID, updateReq.OriginSSL)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"origin_ssl": updateReq.OriginSSL}, nil
	}

	// --- BRANCH 2: Proxy Status Update ---

	// A. Calculate Deletion for Old State
	contentToDelete := record.Content
	typeToDelete := record.Type

	shouldHaveBeenProxied := record.Proxied
	if isNonProxiable(record.Type) {
		shouldHaveBeenProxied = false
	}

	if shouldHaveBeenProxied {
		contentToDelete = s.Cfg.WafPublicIP
		typeToDelete = "A"
	}

	// B. Delete Old from PowerDNS
	if err := database.DeletePowerDNSRecordByContent(record.Name, typeToDelete, contentToDelete); err != nil {
		return nil, fmt.Errorf("failed to delete old DNS entry: %v", err)
	}

	// C. Update MongoDB
	if err := database.UpdateDNSRecordProxy(s.Mongo, recordID, updateReq.Proxied); err != nil {
		return nil, err
	}

	// D. Add New to PowerDNS
	if err := database.AddPowerDNSRecord(record.Name, record.Type, record.Content, updateReq.Proxied, s.Cfg.WafPublicIP); err != nil {
		return nil, fmt.Errorf("failed to add new DNS entry: %v", err)
	}

	return map[string]interface{}{"proxied": updateReq.Proxied}, nil
}

func (s *DNSService) DeleteRecord(recordID, userID string) error {
	// 1. Fetch & Verify
	record, err := database.GetDNSRecordByID(s.Mongo, recordID)
	if err != nil {
		return errors.New("record not found")
	}
	domain, err := database.GetDomainByID(s.Mongo, record.DomainID)
	if err != nil || domain.UserID != userID {
		return errors.New("unauthorized")
	}

	// 2. Determine SQL Content to Delete
	sqlType := record.Type
	sqlContent := record.Content

	if record.Proxied && !isNonProxiable(record.Type) {
		sqlType = "A"
		sqlContent = s.Cfg.WafPublicIP
	}

	// 3. Delete from PowerDNS
	if err := database.DeletePowerDNSRecordByContent(record.Name, sqlType, sqlContent); err != nil {
		return fmt.Errorf("backend delete failed: %v", err)
	}

	// 4. Delete from Mongo
	return database.DeleteDNSRecord(s.Mongo, recordID)
}

// Helpers

func (s *DNSService) validateContent(rType, content string) error {
	switch rType {
	case "A":
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() == nil {
			return errors.New("content must be a valid IPv4 address")
		}
	case "AAAA":
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() != nil {
			return errors.New("content must be a valid IPv6 address")
		}
	case "CNAME":
		if net.ParseIP(content) != nil {
			return errors.New("CNAME content must be a domain name, not IP")
		}
		if !domainRegex.MatchString(strings.TrimSuffix(content, ".")) {
			return errors.New("invalid domain format")
		}
	case "MX", "NS":
		if !domainRegex.MatchString(strings.TrimSuffix(content, ".")) {
			return errors.New("invalid domain format")
		}
	case "TXT":
		if len(content) > 2048 {
			return errors.New("TXT record too long")
		}
	}
	return nil
}

func (s *DNSService) checkConflicts(domainID, name, rType, content string) error {
	conflictTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}

	if rType == "CNAME" {
		for _, t := range conflictTypes {
			exists, err := database.CheckDNSRecordExists(s.Mongo, domainID, name, t)
			if err != nil {
				return err
			}
			if exists {
				return errors.New("CNAME record cannot coexist with other records")
			}
		}
	} else {
		exists, err := database.CheckDNSRecordExists(s.Mongo, domainID, name, "CNAME")
		if err != nil {
			return err
		}
		if exists {
			return errors.New("CNAME record already exists for this hostname")
		}

		// Check duplicates
		exists, err = database.CheckDuplicateDNSRecord(s.Mongo, domainID, name, rType, content)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("duplicate record already exists")
		}
	}
	return nil
}

func isNonProxiable(rType string) bool {
	return rType == "TXT" || rType == "MX" || rType == "NS" || rType == "SOA"
}
