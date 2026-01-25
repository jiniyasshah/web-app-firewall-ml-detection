package middleware

import (
	"net/http"
	"strings"
	"web-app-firewall-ml-detection/internal/config"
)

func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestOrigin := r.Header.Get("Origin")

			// Check if origin is allowed based on Config
			for _, origin := range cfg.AllowedOrigins {
				if strings.TrimSpace(origin) == requestOrigin {
					w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
					break
				}
			}

			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

			// Handle Preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}