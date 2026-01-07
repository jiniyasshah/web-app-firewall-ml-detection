package detector

import (
	"regexp"
	"time"
)

// --- USER & AUTH MODELS ---

type User struct {
	ID       string `bson:"_id,omitempty" json:"id"`
	Name     string `bson:"name" json:"name"`
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"-"`
}

type UserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Domain struct {
	ID          string    `bson:"_id,omitempty" json:"id"`
	UserID      string    `bson:"user_id" json:"user_id"`
	Name        string    `bson:"name" json:"name"`
	Nameservers []string  `bson:"nameservers" json:"nameservers"`
	Status      string    `bson:"status" json:"status"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
}

type DNSRecord struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	DomainID  string    `bson:"domain_id" json:"domain_id"`
	Name      string    `bson:"name" json:"name"`
	Type      string    `bson:"type" json:"type"`
	Content   string    `bson:"content" json:"content"`
	TTL       int       `bson:"ttl" json:"ttl"`
	Proxied   bool      `bson:"proxied" json:"proxied"`
	OriginSSL bool      `bson:"origin_ssl" json:"origin_ssl"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

// --- WAF MODELS ---

type WAFRule struct {
	ID         string      `bson:"_id,omitempty" json:"id"`
	OwnerID    string      `bson:"owner_id,omitempty" json:"owner_id"`
	Name       string      `bson:"name" json:"name"`
	Conditions []Condition `bson:"conditions" json:"conditions"`
	OnMatch    Action      `bson:"on_match" json:"on_match"`
	Enabled    bool        `bson:"-" json:"enabled"`
}

type RulePolicy struct {
	ID       string `bson:"_id,omitempty" json:"id"`
	UserID   string `bson:"user_id" json:"user_id"`
	RuleID   string `bson:"rule_id" json:"rule_id"`
	DomainID string `bson:"domain_id,omitempty" json:"domain_id"`
	Enabled  bool   `bson:"enabled" json:"enabled"`
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

// --- LOGGING MODELS (Moved from logger/logger.go) ---

type FullRequest struct {
	Method  string              `bson:"method" json:"method"`
	URL     string              `bson:"url" json:"url"`
	Headers map[string][]string `bson:"headers" json:"headers"`
	Body    string              `bson:"body" json:"body"`
}

type AttackLog struct {
	ID             interface{} `bson:"_id,omitempty" json:"_id"` // Matches MongoDB ID
	UserID         string      `bson:"user_id" json:"user_id"`
	DomainID       string      `bson:"domain_id" json:"domain_id"`
	Timestamp      time.Time   `bson:"timestamp" json:"timestamp"`
	IP             string      `bson:"ip" json:"ip"`
	RequestPath    string      `bson:"request_path" json:"request_path"`
	Reason         string      `bson:"reason" json:"reason"`
	Source         string      `bson:"source" json:"source"`
	Tags           []string    `bson:"tags" json:"tags"`
	Action         string      `bson:"action" json:"action"`
	Score          int         `bson:"score,omitempty" json:"score,omitempty"`
	MLConfidence   float64     `bson:"ml_confidence,omitempty" json:"ml_confidence,omitempty"`
	Request        FullRequest `bson:"request" json:"request"`
	TriggerPayload string      `bson:"trigger_payload" json:"trigger_payload"`
}