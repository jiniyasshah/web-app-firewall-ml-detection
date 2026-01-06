package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// JWT Secret (Use os.Getenv in production)
var JWTSecret = []byte("super_secret_waf_key_change_me")

func (h *APIHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use UserInput for decoding the request
	var input detector.UserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.WriteJSONError(w, "Invalid JSON Body", http.StatusBadRequest)
		return
	}

	// Basic Validation
	if input.Email == "" || input.Password == "" || input.Name == "" {
		h.WriteJSONError(w, "Name, Email and Password are required", http.StatusBadRequest)
		return
	}

	// Hash Password
	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), 10)
	if err != nil {
		h.WriteJSONError(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Create User struct for database
	user := detector.User{
		Name:     input.Name,
		Email:    input.Email,
		Password: string(hashed),
	}

	// Save to DB
	if err := database.CreateUser(h.MongoClient, user); err != nil {
		h.WriteJSONError(w, "Registration failed:  "+err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message":  "User registered successfully"})
}

func (h *APIHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use UserInput instead of User
	var input detector.UserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.WriteJSONError(w, "Invalid JSON Body", http.StatusBadRequest)
		return
	}

	user, err := database.GetUserByEmail(h.MongoClient, input.Email)
	if err != nil {
		h.WriteJSONError(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		h.WriteJSONError(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT
	expiration := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"email":   user.Email,
		"exp":     expiration.Unix(),
	})

	tokenString, err := token.SignedString(JWTSecret)
	if err != nil {
		h.WriteJSONError(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Determine if we are in Production
	isProd := os.Getenv("APP_ENV") == "production"

	// Dynamic Domain Logic:
	// - Prod: ".minishield.tech" (Allows cookie sharing between api. and www.)
	// - Dev:  "" (Empty string defaults to "Host Only", required for localhost)
	cookieDomain := ""
	if isProd {
		cookieDomain = ".minishield.tech"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		Expires:  expiration,
		HttpOnly: true,
		Path:     "/",
		
		// Dynamic Settings
		Domain:   cookieDomain,
		Secure:   true,               // True in Prod (HTTPS), False in Dev (HTTP)
		SameSite: http.SameSiteNoneMode, // Lax is best for normal navigation
	})

	// Return User Info
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"user":  map[string]string{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
		},
	})
}

func (h *APIHandler) CheckAuth(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		h.WriteJSONError(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Fetch full user details to get the Name
	user, err := database.GetUserByID(h.MongoClient, userID)
	userName := "Unknown"
	if err == nil {
		userName = user.Name
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"user": map[string]string{
			"id":   userID,
			"name": userName,
		},
	})
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			// MANUAL JSON ERROR RESPONSE
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "error",
				"message": "Unauthorized: No session cookie",
			})
			return
		}

		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return JWTSecret, nil
		})

		if err != nil || !token.Valid {
			// MANUAL JSON ERROR RESPONSE
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "error",
				"message": "Unauthorized: Invalid token",
			})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			// MANUAL JSON ERROR RESPONSE
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "error",
				"message": "Unauthorized: Invalid claims",
			})
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			// MANUAL JSON ERROR RESPONSE
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "error",
				"message": "Unauthorized",
			})
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next(w, r.WithContext(ctx))
	}
}

func (h *APIHandler) Logout(w http.ResponseWriter, r *http.Request) {
    // 1. Determine Environment (MUST match Login logic)
    isProd := os.Getenv("APP_ENV") == "production"

    cookieDomain := ""
    if isProd {
        cookieDomain = ".minishield.tech"
    }

    // 2. Clear the Cookie
    // We set the same Name, Path, Domain, Secure, and HttpOnly attributes.
    // We only change Value to "" and Expires to a past date.
    http.SetCookie(w, &http.Cookie{
        Name:     "auth_token",
        Value:    "",              // Empty value
        Expires:  time.Unix(0, 0), // Expire immediately (1970)
        
        // These MUST match what you set in Login:
        HttpOnly: true,
        Path:     "/",
        Domain:   cookieDomain,    // Crucial: Match the domain!
        Secure:   true,         // Crucial: Match the Secure flag!
        SameSite: http.SameSiteLaxMode,
		
    })

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}