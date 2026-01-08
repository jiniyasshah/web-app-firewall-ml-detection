package middleware

import (
	"context"
	"net/http"
	"os"
	"web-app-firewall-ml-detection/pkg/response"

	"github.com/golang-jwt/jwt/v5"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// UserIDKey is the context key for user ID
	UserIDKey contextKey = "user_id"
	// EmailKey is the context key for email
	EmailKey contextKey = "email"
)

// getJWTSecret returns the JWT secret from environment or default
func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "super_secret_waf_key_change_me"
	}
	return []byte(secret)
}

// Auth is a middleware that validates JWT tokens
func Auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			response.Unauthorized(w, "Unauthorized: No session cookie")
			return
		}

		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return getJWTSecret(), nil
		})

		if err != nil || !token.Valid {
			response.Unauthorized(w, "Unauthorized: Invalid token")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			response.Unauthorized(w, "Unauthorized: Invalid claims")
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			response.Unauthorized(w, "Unauthorized")
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		
		// Optionally add email if present
		if email, ok := claims["email"].(string); ok {
			ctx = context.WithValue(ctx, EmailKey, email)
		}

		next(w, r.WithContext(ctx))
	}
}

// GetUserID retrieves user ID from request context
func GetUserID(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value(UserIDKey).(string)
	return userID, ok
}

// GetEmail retrieves email from request context
func GetEmail(r *http.Request) (string, bool) {
	email, ok := r.Context().Value(EmailKey).(string)
	return email, ok
}
