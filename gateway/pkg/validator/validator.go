package validator

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	// ErrInvalidEmail is returned when email format is invalid
	ErrInvalidEmail = errors.New("invalid email format")
	// ErrEmptyField is returned when a required field is empty
	ErrEmptyField = errors.New("field cannot be empty")
	// ErrInvalidIP is returned when IP address is invalid
	ErrInvalidIP = errors.New("invalid IP address")
	// ErrInvalidDomain is returned when domain format is invalid
	ErrInvalidDomain = errors.New("invalid domain format")
)

var (
	emailRegex  = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// Email validates email format
func Email(email string) error {
	if email == "" {
		return ErrEmptyField
	}
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

// Required checks if a string field is not empty
func Required(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New(fieldName + " is required")
	}
	return nil
}

// IPv4 validates IPv4 address format
func IPv4(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return ErrInvalidIP
	}
	return nil
}

// IPv6 validates IPv6 address format
func IPv6(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return errors.New("invalid IPv6 address")
	}
	return nil
}

// Domain validates domain name format
func Domain(domain string) error {
	if domain == "" {
		return ErrEmptyField
	}
	
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	
	if !domainRegex.MatchString(domain) {
		return ErrInvalidDomain
	}
	return nil
}

// TTL validates TTL value (must be between 60 and 86400)
func TTL(ttl int) error {
	if ttl < 60 || ttl > 86400 {
		return errors.New("TTL must be between 60 and 86400 seconds")
	}
	return nil
}

// MinLength checks if string meets minimum length requirement
func MinLength(value string, min int, fieldName string) error {
	if len(value) < min {
		return errors.New(fieldName + " must be at least " + strconv.Itoa(min) + " characters")
	}
	return nil
}

// MaxLength checks if string doesn't exceed maximum length
func MaxLength(value string, max int, fieldName string) error {
	if len(value) > max {
		return errors.New(fieldName + " must not exceed " + strconv.Itoa(max) + " characters")
	}
	return nil
}

// IsNotIP checks if the value is not an IP address
func IsNotIP(value string) bool {
	return net.ParseIP(value) == nil
}
