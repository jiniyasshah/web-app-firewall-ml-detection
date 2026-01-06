package detector

import (
	"regexp"
	"time"
)

// --- USER & AUTH MODELS ---

type User struct {
	ID       string `bson:"_id,omitempty" json:"id"`
	Name     string `bson:"name" json:"name"`           // [NEW] User's Display Name
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"-"`          // Password is never output to JSON
}
// UserInput is for registration/login requests
type UserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Domain struct {
	ID          string    `bson:"_id,omitempty" json:"id"`
	UserID      string    `bson:"user_id" json:"user_id"`
	Name        string    `bson:"name" json:"name"`           // e.g. "myapp.com"
	Nameservers []string  `bson:"nameservers" json:"nameservers"`
	Status      string    `bson:"status" json:"status"`       // "pending_verification", "active"     // Is WAF enabled for this domain?
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
}

// DNSRecord represents individual DNS records for a domain
type DNSRecord struct {
	ID        string `bson:"_id,omitempty" json:"id"`
	DomainID  string `bson:"domain_id" json:"domain_id"`
	Name      string `bson:"name" json:"name"`         // e.g. "@", "www", "api"
	Type      string `bson:"type" json:"type"`         // "A", "CNAME", "MX", etc.
	Content   string `bson:"content" json:"content"`   // "1.2.3.4" or "example.com"
	TTL       int    `bson:"ttl" json:"ttl"`           // 300, 3600, etc.
	Proxied   bool   `bson:"proxied" json:"proxied"`   // Is this record protected by WAF?
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

// --- WAF MODELS ---

type WAFRule struct {
	ID         string      `bson:"_id,omitempty" json:"id"`
	OwnerID    string      `bson:"owner_id,omitempty" json:"owner_id"` // Empty = Global, Set = Private
	Name       string      `bson:"name" json:"name"`
	Conditions []Condition `bson:"conditions" json:"conditions"`
	OnMatch    Action      `bson:"on_match" json:"on_match"`
	
	// Enabled is a virtual field for the UI, calculated from Policies
	Enabled    bool        `bson:"-" json:"enabled"` 
}

type RulePolicy struct {
	ID        string `bson:"_id,omitempty" json:"id"`
	UserID    string `bson:"user_id" json:"user_id"`
	RuleID    string `bson:"rule_id" json:"rule_id"`
	DomainID  string `bson:"domain_id,omitempty" json:"domain_id"`
	Enabled   bool   `bson:"enabled" json:"enabled"`
}

type Condition struct {
	Field         string         `bson:"field" json:"field"`
	Operator      string         `bson:"operator" json:"operator"`
	Value         interface{}    `bson:"value" json:"value"`
	CompiledRegex *regexp.Regexp `bson:"-" json:"-"`
}

type Action struct {
	ScoreAdd  int      `bson:"score_add" json:"score_add"`
	Tags      []string `bson:"tags" json:"tags"`
	HardBlock bool     `bson:"hard_block" json:"hard_block"`
}
