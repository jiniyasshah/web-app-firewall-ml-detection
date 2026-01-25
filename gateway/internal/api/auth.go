package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils"

	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	Service *service.AuthService
}

func NewAuthHandler(s *service.AuthService) *AuthHandler {
	return &AuthHandler{Service: s}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input models.UserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}
	if err := h.Service.Register(input); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}
	utils.WriteMessage(w, "User registered successfully", http.StatusCreated)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input models.UserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	token, user, err := h.Service.Login(input.Email, input.Password)
	if err != nil {
		utils.WriteError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	cookieDomain := ""
	if h.Service.Cfg.AppEnv == "production" {
		cookieDomain = ".minishield.tech"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		Domain:   cookieDomain,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	utils.WriteSuccess(w, map[string]interface{}{
		"message": "Login successful",
		"user":    user,
	}, http.StatusOK)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookieDomain := ""
	if h.Service.Cfg.AppEnv == "production" {
		cookieDomain = ".minishield.tech"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
		Domain:   cookieDomain,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	utils.WriteMessage(w, "Logged out", http.StatusOK)
}

func (h *AuthHandler) CheckAuth(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		utils.WriteError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := h.Service.GetUser(userID)
	if err != nil {
		utils.WriteError(w, "User not found", http.StatusNotFound)
		return
	}
	utils.WriteSuccess(w, map[string]interface{}{
		"authenticated": true,
		"user":          user,
	}, http.StatusOK)
}

func (h *AuthHandler) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			utils.WriteError(w, "Unauthorized: No session cookie", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return []byte(h.Service.Cfg.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			utils.WriteError(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			utils.WriteError(w, "Unauthorized: Invalid claims", http.StatusUnauthorized)
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			utils.WriteError(w, "Unauthorized: Invalid user ID", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next(w, r.WithContext(ctx))
	}
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// Expecting /api/auth/verify?token=123456789
	token := r.URL.Query().Get("token")
	if token == "" {
		utils.WriteError(w, "Missing verification token", http.StatusBadRequest)
		return
	}

	if err := h.Service.VerifyEmail(token); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Redirect user to the frontend login page with a success query param
	http.Redirect(w, r, h.Service.Cfg.FrontendURL+"/login?verified=true", http.StatusSeeOther)
}