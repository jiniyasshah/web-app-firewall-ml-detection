package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
    // Define the origin server to reverse proxy to (your origin URL)
    origin := "http://origin:3000" // Change this to actual origin URL (e.g., the Juice Shop or any HTTP server)

    // Parse the origin URL
    originURL, err := url.Parse(origin)
    if err != nil {
        log.Fatal("Error parsing origin URL:", err)
    }

    // Create a reverse proxy
    proxy := httputil.NewSingleHostReverseProxy(originURL)

    // Set up the HTTPS server with TLS certificates
    server := &http.Server{
        Addr:    ":8080", // The port where the Go server will listen for incoming HTTPS requests
        Handler: proxy,   // Use the reverse proxy as the handler
        TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS13, // Use modern TLS security
        },
    }

    // Start the HTTPS server
    log.Println("Starting HTTPS server on port 8080...")
    err = server.ListenAndServeTLS("certs/waf.crt", "certs/waf.key") // Use the self-signed certificates generated earlier
    if err != nil {
        log.Fatal("Failed to start HTTPS server:", err)
    }
}
