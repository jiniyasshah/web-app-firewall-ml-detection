package detector

import (
	"regexp"
	"time"
)

// --- USER & AUTH MODELS ---
type User struct {
	ID       string `bson:"_id,omitempty" json:"id"`
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"password"` 
}

type Domain struct {
	ID             string    `bson:"_id,omitempty" json:"_id"`
	UserID         string    `bson:"user_id" json:"user_id"`
	Name           string    `bson:"name" json:"name"`           // e.g. "myapp.com"
	TargetURL      string    `bson:"target_url" json:"target_url"`
	Nameservers    []string  `bson:"nameservers" json:"nameservers"`
	Status         string    `bson:"status" json:"status"`
	CreatedAt      time.Time `bson:"created_at" json:"created_at"`
}

// --- UPDATED WAF MODELS ---

// WAFRule defines *what* the rule does.
type WAFRule struct {
	ID         string      `bson:"_id,omitempty" json:"_id"`
	OwnerID    string      `bson:"owner_id,omitempty" json:"owner_id"` // Empty = Global/System Rule. Set = Private Rule.
	Name       string      `bson:"name" json:"name"`
	Conditions []Condition `bson:"conditions" json:"conditions"`
	OnMatch    Action      `bson:"on_match" json:"on_match"`
	
	// Internal field for logic, not stored in DB directly if using policies
	Enabled    bool        `bson:"-" json:"enabled"` 
}

// RulePolicy defines *how* a user applies a rule (Global or Private).
// This decouples the definition from the configuration.
type RulePolicy struct {
	ID        string `bson:"_id,omitempty" json:"id"`
	UserID    string `bson:"user_id" json:"user_id"`
	RuleID    string `bson:"rule_id" json:"rule_id"`
	
	// If DomainID is empty, this policy applies to ALL domains owned by UserID
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