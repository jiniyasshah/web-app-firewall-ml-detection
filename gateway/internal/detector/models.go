package detector

import "regexp"

// WAFRule matching the DB schema
type WAFRule struct {
	ID         string      `bson:"_id" json:"_id"`
	Name       string      `bson:"name" json:"name"`
	Enabled    bool        `bson:"enabled" json:"enabled"`
	Conditions []Condition `bson:"conditions" json:"conditions"`
	OnMatch    Action      `bson:"on_match" json:"on_match"`
}

type Condition struct {
	Field    string         `bson:"field" json:"field"`
	Operator string         `bson:"operator" json:"operator"`
	Value    interface{}    `bson:"value" json:"value"`
	// OPTIMIZATION: Store compiled regex here so we don't re-compile it
	CompiledRegex *regexp.Regexp `bson:"-" json:"-"` 
}

type Action struct {
	ScoreAdd  int      `bson:"score_add" json:"score_add"`
	Tags      []string `bson:"tags" json:"tags"`
	HardBlock bool     `bson:"hard_block" json:"hard_block"`
}