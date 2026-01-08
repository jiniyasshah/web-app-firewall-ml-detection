package config

import (
	"os"
	"strings"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	DNS      DNSConfig
	ML       MLConfig
	JWT      JWTConfig
	CORS     CORSConfig
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port        string
	Environment string
	WafPublicIP string
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	MongoURI string
}

// DNSConfig holds DNS database configuration
type DNSConfig struct {
	User string
	Pass string
	Host string
	Name string
}

// MLConfig holds ML service configuration
type MLConfig struct {
	URL string
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret string
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:        getEnv("PORT", "443"),
			Environment: getEnv("APP_ENV", "development"),
			WafPublicIP: getEnv("WAF_PUBLIC_IP", "64.227.156.70"),
		},
		Database: DatabaseConfig{
			MongoURI: getEnv("MONGO_URI", "mongodb://mongo:27017"),
		},
		DNS: DNSConfig{
			User: getEnv("DNS_DB_USER", "pdns"),
			Pass: getEnv("DNS_DB_PASS", "pdns_password"),
			Host: getEnv("DNS_DB_HOST", "dns_sql_db"),
			Name: getEnv("DNS_DB_NAME", "powerdns"),
		},
		ML: MLConfig{
			URL: getEnv("ML_URL", "http://ml_scorer:8000/predict"),
		},
		JWT: JWTConfig{
			Secret: getEnv("JWT_SECRET", "super_secret_waf_key_change_me"),
		},
		CORS: CORSConfig{
			AllowedOrigins: parseOrigins(getEnv("FRONTEND_URL", "https://www.minishield.tech")),
		},
	}
}

// IsProduction returns true if running in production
func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// GetOriginURL returns the default origin URL
func GetOriginURL() string {
	return getEnv("ORIGIN_URL", "http://origin:3000")
}

// getEnv retrieves an environment variable or returns a fallback value
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// parseOrigins splits a comma-separated list of origins
func parseOrigins(origins string) []string {
	parts := strings.Split(origins, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
