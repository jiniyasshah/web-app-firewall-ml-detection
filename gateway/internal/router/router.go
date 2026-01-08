package router

import (
	"net/http"

	"web-app-firewall-ml-detection/internal/api"
	"web-app-firewall-ml-detection/pkg/middleware"
)

// Setup configures all API routes and returns the configured mux
func Setup(apiHandler *api.APIHandler) *http.ServeMux {
	mux := http.NewServeMux()

	// System Status (Public)
	mux.HandleFunc("/api/status", apiHandler.SystemStatus)

	// Authentication Routes (Public except /check)
	mux.HandleFunc("/api/auth/register", apiHandler.Register)
	mux.HandleFunc("/api/auth/login", apiHandler.Login)
	mux.HandleFunc("/api/auth/logout", apiHandler.Logout)
	mux.HandleFunc("/api/auth/check", middleware.Auth(apiHandler.CheckAuth))

	// SSE Stream (Public for now - consider adding auth if needed)
	mux.HandleFunc("/api/stream", apiHandler.SSEHandler)

	// Domain Management (Protected)
	mux.HandleFunc("/api/domains", middleware.Auth(apiHandler.ListDomains))
	mux.HandleFunc("/api/domains/add", middleware.Auth(apiHandler.AddDomain))
	mux.HandleFunc("/api/domains/verify", middleware.Auth(apiHandler.VerifyDomain))

	// DNS Record Management (Protected)
	mux.HandleFunc("/api/dns/records", middleware.Auth(apiHandler.ManageRecords))

	// WAF Rules Management (Protected)
	mux.HandleFunc("/api/rules/global", middleware.Auth(apiHandler.GetGlobalRules))
	mux.HandleFunc("/api/rules/custom", middleware.Auth(apiHandler.GetCustomRules))
	mux.HandleFunc("/api/rules/custom/add", middleware.Auth(apiHandler.AddCustomRule))
	mux.HandleFunc("/api/rules/custom/delete", middleware.Auth(apiHandler.DeleteCustomRule))
	mux.HandleFunc("/api/rules/toggle", middleware.Auth(apiHandler.ToggleRule))

	// Logs (Protected)
	mux.HandleFunc("/api/logs/secure", middleware.Auth(apiHandler.SecuredLogsHandler))

	// WAF Handler - Catches all other traffic
	mux.HandleFunc("/", apiHandler.WAFHandler)

	return mux
}
