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

		//Token Versioning ---
		user, err := h.Service.GetUser(userID)
		if err != nil {
			utils.WriteError(w, "Unauthorized: User not found", http.StatusUnauthorized)
			return
		}

		// JWT stores numbers as float64
		tokenVersion := 0
		if tv, ok := claims["token_version"].(float64); ok {
			tokenVersion = int(tv)
		}

		// If the DB version is different from the Token version, the password was changed!
		if user.TokenVersion != tokenVersion {
			utils.WriteError(w, "Session expired. Please log in again.", http.StatusUnauthorized)
			return
		}
		// ----------------------------------------------------

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next(w, r.WithContext(ctx))
	}
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		utils.WriteError(w, "Missing verification token", http.StatusBadRequest)
		return
	}

	if err := h.Service.VerifyEmail(token); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// [UPDATED] Return JSON Success instead of Redirect
	utils.WriteSuccess(w, map[string]string{
		"message": "Email verified successfully",
	}, http.StatusOK)
}

func (h *AuthHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	
	var input struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.NewPassword == "" {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if err := h.Service.UpdatePassword(userID, input.OldPassword, input.NewPassword); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, map[string]string{"message": "Password updated successfully"}, http.StatusOK)
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Email == "" {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if err := h.Service.ForgotPassword(input.Email); err != nil {
		utils.WriteError(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	// Always return success to prevent email enumeration
	utils.WriteSuccess(w, map[string]string{"message": "If that email exists, a reset link has been sent."}, http.StatusOK)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Token == "" || input.NewPassword == "" {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if err := h.Service.ResetPassword(input.Token, input.NewPassword); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, map[string]string{"message": "Password has been reset successfully. You can now log in."}, http.StatusOK)
}

func (h *AuthHandler) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	
	var input struct {
		NewEmail string `json:"new_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.NewEmail == "" {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if err := h.Service.RequestEmailChange(userID, input.NewEmail); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, map[string]string{"message": "Verification link sent to your new email."}, http.StatusOK)
}

// [NEW] Handler for the link click
func (h *AuthHandler) VerifyEmailChange(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		utils.WriteError(w, "Missing token", http.StatusBadRequest)
		return
	}

	if err := h.Service.VerifyEmailChange(token); err != nil {
		utils.WriteError(w, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WriteSuccess(w, map[string]string{"message": "Email updated successfully!"}, http.StatusOK)
}