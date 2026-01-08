package api

import (
	"encoding/json"
	"net/http"
	"web-app-firewall-ml-detection/internal/service/auth"
	"web-app-firewall-ml-detection/pkg/middleware"
	"web-app-firewall-ml-detection/pkg/response"
)

func (h *APIHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.MethodNotAllowed(w)
		return
	}

	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON Body")
		return
	}

	authService := auth.NewService(h.MongoClient, h.Config.JWT.Secret)
	if err := authService.Register(req); err != nil {
		response.BadRequest(w, err.Error())
		return
	}

	response.Created(w, nil, "User registered successfully")
}

func (h *APIHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.MethodNotAllowed(w)
		return
	}

	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON Body")
		return
	}

	authService := auth.NewService(h.MongoClient, h.Config.JWT.Secret)
	token, user, err := authService.Login(req)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}

	// Set authentication cookie
	cookie := auth.CreateAuthCookie(token, h.Config.IsProduction())
	http.SetCookie(w, cookie)

	// Return user info
	response.Success(w, map[string]interface{}{
		"user": user,
	}, "Login successful")
}

func (h *APIHandler) CheckAuth(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		response.InternalServerError(w, "Server Error")
		return
	}

	authService := auth.NewService(h.MongoClient, h.Config.JWT.Secret)
	user, err := authService.GetUserInfo(userID)
	if err != nil {
		response.InternalServerError(w, "Failed to retrieve user information")
		return
	}

	response.Success(w, map[string]interface{}{
		"authenticated": true,
		"user":          user,
	}, "")
}

func (h *APIHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie := auth.ClearAuthCookie()
	http.SetCookie(w, cookie)
	response.Success(w, nil, "Logged out")
}
