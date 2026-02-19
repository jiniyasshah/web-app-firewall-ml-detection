package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	AppEnv         string
	Port           string
	MongoURI       string
	FrontendURL    string
	AllowedOrigins []string

	// WAF Settings
	OriginURL   string
	MLURL       string
	WafPublicIP string

	//Limits
	RateLimit     int // Existing per-IP limit
    DDOSLimit     int // Per-Domain limit

	// DNS DB
	DNSUser string
	DNSPass string
	DNSHost string
	DNSName string
	
	// Email Settings
    SMTPHost     string
    SMTPPort     string
    SMTPUser     string
    SMTPPass     string
    SMTPFrom     string	

	// Security
    JWTSecret        string
    RecaptchaSiteKey string 
    RecaptchaSecret  string 
}

func Load() *Config {
	appEnv := getEnv("APP_ENV", "development")
	
	// Base allowed origins from Env
	frontendURL := getEnv("FRONTEND_URL", "https://www.minishield.tech")
	origins := strings.Split(frontendURL, ",")

	// Automatically allow localhost:3000 in development
	if appEnv == "development" {
		origins = append(origins, "http://localhost:3000")
	}

	return &Config{
		AppEnv:         appEnv,
		Port:           getEnv("PORT", "443"),
		MongoURI:       getEnv("MONGO_URI", "mongodb://mongo:27017"),
		FrontendURL:    frontendURL,
		AllowedOrigins: origins,

		OriginURL:   getEnv("ORIGIN_URL", "http://origin:3000"),
		MLURL:       getEnv("ML_URL", "http://ml_scorer:8000/predict"),
		WafPublicIP: getEnv("WAF_PUBLIC_IP", "157.245.100.147"),

		RateLimit: getEnvAsInt("RATE_LIMIT", 100),
        DDOSLimit: getEnvAsInt("DDOS_LIMIT", 10000),

		DNSUser: getEnv("DNS_DB_USER", "pdns"),
		DNSPass: getEnv("DNS_DB_PASS", "pdns_password"),
		DNSHost: getEnv("DNS_DB_HOST", "dns_sql_db"),
		DNSName: getEnv("DNS_DB_NAME", "powerdns"),

        SMTPUser: getEnv("SMTP_USER", "your-email@gmail.com"),
        SMTPPass: getEnv("SMTP_PASS", "app-password"),

		JWTSecret: getEnv("JWT_SECRET", "super_secret_waf_key_change_me"),
		RecaptchaSiteKey: getEnv("RECAPTCHA_SITE_KEY", ""), 
        RecaptchaSecret:  getEnv("RECAPTCHA_SECRET", ""),  
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// Helper for int envs
func getEnvAsInt(key string, fallback int) int {
    if value, exists := os.LookupEnv(key); exists {
        if i, err := strconv.Atoi(value); err == nil {
            return i
        }
    }
    return fallback
}