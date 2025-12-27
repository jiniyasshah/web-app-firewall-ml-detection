package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// JWT Secret (Use os.Getenv in production)
var JWTSecret = []byte("super_secret_waf_key_change_me")

// ---------------------------------------------------------
// AUTHENTICATION HANDLERS
// ---------------------------------------------------------

func (h *APIHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input detector.User
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON Body", http.StatusBadRequest)
		return
	}

	// Hash Password
	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), 10)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	input.Password = string(hashed)

	// Save to DB
	if err := database.CreateUser(h.MongoClient, input); err != nil {
		http.Error(w, "Registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// [UPDATED] Login now sets an HttpOnly Cookie
func (h *APIHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input detector.User
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON Body", http.StatusBadRequest)
		return
	}

	user, err := database.GetUserByEmail(h.MongoClient, input.Email)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT
	expiration := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     expiration.Unix(),
	})

	tokenString, err := token.SignedString(JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// [SECURE CHANGE] Set HttpOnly Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		Expires:  expiration,
		HttpOnly: true,                   // JavaScript cannot access this
		Secure:   false,                  // Set to true in Production (HTTPS)
		SameSite: http.SameSiteLaxMode,   // Protects against CSRF
		Path:     "/",
	})

	// Return success (no token in body)
	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful"})
}

func (h *APIHandler) CheckAuth(w http.ResponseWriter, r *http.Request) {
    // 1. Retrieve user_id from context (set by AuthMiddleware)
    userID, ok := r.Context().Value("user_id").(string)
    if !ok {
        http.Error(w, "Server Error: User ID not found in context", http.StatusInternalServerError)
        return
    }

    // 2. (Optional) Fetch full user details from DB if you need the email/role
    // user, err := database.GetUserByID(h.MongoClient, userID) ...
    
    // 3. Return status
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "authenticated": true,
        "user_id":       userID,
        "message":       "User is logged in",
    })
}

// [UPDATED] Middleware now reads from Cookie
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Try to get token from Cookie
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "Unauthorized: No session cookie", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value

		// 2. Parse & Validate Token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return JWTSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Unauthorized: Invalid claims", http.StatusUnauthorized)
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			http.Error(w, "Unauthorized: Missing user_id", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next(w, r.WithContext(ctx))
	}
}

// [NEW] Logout Handler (Clears the cookie and returns JSON)
func (h *APIHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// 1. Invalidate the Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})

	// 2. Return Success Message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}