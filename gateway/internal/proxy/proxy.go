package proxy

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"web-app-firewall-ml-detection/internal/service"
)

// NewReverseProxy creates the underlying proxy that forwards traffic
func NewReverseProxy(wafService *service.WAFService, page502 []byte) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		incomingHost := req.Host
		
		// Ask Service for target
		targetURL := wafService.GetTargetURL(incomingHost)

		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Header.Set("X-Forwarded-Host", incomingHost)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Real-IP", req.RemoteAddr)
	}

	return &httputil.ReverseProxy{
		Director: director,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("🔥 Proxy Error for %s: %v", r.Host, err)
			if r.Context().Err() != nil {
				return
			}
			w.WriteHeader(http.StatusBadGateway)
			w.Header().Set("Content-Type", "text/html")
			w.Write(page502)
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}