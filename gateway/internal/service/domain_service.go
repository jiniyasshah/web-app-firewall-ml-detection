package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/mongo"
)

var realNameservers = []string{
	"jiniyas", "rabin", "niraj", "sabin", "rita",
	"sneha", "exam", "bikalpa", "raju", "dhiren", "sanket",
}

const nsSuffix = ".ns.minishield.tech"

// RDAP Response Structure
type RDAPResponse struct {
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
}

type DomainService struct {
	Mongo *mongo.Client
}

func NewDomainService(client *mongo.Client) *DomainService {
	return &DomainService{Mongo: client}
}

func (s *DomainService) ListDomains(userID string) ([]models.Domain, error) {
	return database.GetDomainsByUser(s.Mongo, userID)
}

func (s *DomainService) AddDomain(input models.DomainInput, userID string) (*models.Domain, error) {
	// 1. Strict Subdomain Policy Check
	rootZone := getRootDomain(input.Name)
	if rootZone != input.Name {
		existingRoot, err := database.GetDomainByName(s.Mongo, rootZone)
		if err == nil && existingRoot != nil {
			return nil, fmt.Errorf("root domain '%s' exists. Please add '%s' as an A Record", rootZone, input.Name)
		}
	}

	// 2. Assign 2 Random Real Nameservers
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	idx1 := r.Intn(len(realNameservers))
	idx2 := r.Intn(len(realNameservers))
	for idx1 == idx2 {
		idx2 = r.Intn(len(realNameservers))
	}

	ns1 := realNameservers[idx1] + nsSuffix
	ns2 := realNameservers[idx2] + nsSuffix

	domain := models.Domain{
		UserID:      userID,
		Name:        input.Name,
		Nameservers: []string{ns1, ns2},
		Status:      "pending_verification",
		CreatedAt:   time.Now(),
	}

	// 3. Save to MongoDB
	createdDomain, err := database.CreateDomain(s.Mongo, domain)
	if err != nil {
		return nil, err
	}

	return &createdDomain, nil
}

// VerifyDomainOwner uses your RDAP Logic
func (s *DomainService) VerifyDomainOwner(domainID, userID string) (bool, map[string]interface{}, error) {
	// 1. Fetch Domain
	domain, err := database.GetDomainByID(s.Mongo, domainID)
	if err != nil {
		return false, nil, errors.New("domain not found")
	}
	if domain.UserID != userID {
		return false, nil, errors.New("unauthorized")
	}

	// 2. Check RDAP (The Security Check)
	foundNS, err := s.checkRegistrarRDAP(domain.Name)
	if err != nil {
		return false, nil, fmt.Errorf("RDAP verification unavailable: %v", err)
	}

	// 3. Compare Found NS vs Assigned NS
	matchedCount := 0
	for _, assignedNS := range domain.Nameservers {
		found := false
		for _, liveNS := range foundNS {
			if strings.EqualFold(liveNS, assignedNS) {
				found = true
				break
			}
		}
		if found {
			matchedCount++
		}
	}

	verified := (matchedCount == len(domain.Nameservers)) && (len(domain.Nameservers) > 0)

	if verified {

		_ = database.RevokeOldOwnership(s.Mongo, domain.Name, domain.ID)

		err = database.CreateDNSZone(domain.Name, domain.Nameservers)
		if err != nil {
			return false, nil, fmt.Errorf("verification passed but DNS provisioning failed: %v", err)
		}


		if err := database.UpdateDomainStatus(s.Mongo, domain.ID, "active"); err != nil {
			return false, nil, err
		}
		return true, nil, nil
	}

	details := map[string]interface{}{
		"assigned_ns":        domain.Nameservers,
		"found_at_registrar": foundNS,
	}
	return false, details, nil
}

func (s *DomainService) checkRegistrarRDAP(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://rdap.org/domain/%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("domain not found in registry")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rdapResp RDAPResponse
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return nil, err
	}

	var nameservers []string
	for _, ns := range rdapResp.Nameservers {
		cleanName := strings.TrimSuffix(ns.LdhName, ".")
		nameservers = append(nameservers, cleanName)
	}

	return nameservers, nil
}


func getRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func (s *DomainService) DeleteDomain(domainID, userID string) error {
	// 1. Fetch & Verify Ownership
	domain, err := database.GetDomainByID(s.Mongo, domainID)
	if err != nil {
		return errors.New("domain not found")
	}
	if domain.UserID != userID {
		return errors.New("unauthorized")
	}

	// 2. If Active/Verified, Remove from PowerDNS 
	if domain.Status == "active" {
		if err := database.DeleteDNSZone(domain.Name); err != nil {
			return fmt.Errorf("failed to delete from DNS backend: %v", err)
		}
	}

	if err := database.DeleteDNSRecordsByDomainID(s.Mongo, domainID); err != nil {
		return fmt.Errorf("failed to delete associated records: %v", err)
	}

	if err := database.DeleteDomain(s.Mongo, domainID); err != nil {
		return fmt.Errorf("failed to delete domain: %v", err)
	}

	return nil
}