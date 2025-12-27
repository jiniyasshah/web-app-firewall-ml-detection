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
	ID             string    `bson:"_id,omitempty" json:"id"`
	UserID         string    `bson:"user_id" json:"user_id"`
	Name           string    `bson:"name" json:"name"`           // e.g. "myapp.com"
	TargetURL      string    `bson:"target_url" json:"target_url"` // Where to proxy (Origin)
	Nameservers    []string  `bson:"nameservers" json:"nameservers"`
	Verified       bool      `bson:"verified" json:"verified"`
	CreatedAt      time.Time `bson:"created_at" json:"created_at"`
}

// --- UPDATED WAF MODELS ---
type WAFRule struct {
	ID         string      `bson:"_id,omitempty" json:"_id"`
	DomainID   string      `bson:"domain_id,omitempty" json:"domain_id"` // Empty = Global Rule
	Name       string      `bson:"name" json:"name"`
	Enabled    bool        `bson:"enabled" json:"enabled"`
	Conditions []Condition `bson:"conditions" json:"conditions"`
	OnMatch    Action      `bson:"on_match" json:"on_match"`
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