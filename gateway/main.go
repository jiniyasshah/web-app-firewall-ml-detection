package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	// Define the origin server to reverse proxy to (your origin URL)
	origin := "http://origin:3000" // The Python server will be the origin for the proxy

	// Parse the origin URL
	originURL, err := url.Parse(origin)
	if err != nil {
		log.Fatal("Error parsing origin URL:", err)
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(originURL)

	// Set up the HTTP server (NGINX will handle TLS/HTTPS termination)
	http.Handle("/", proxy)  // Use the reverse proxy as the handler

	// Start the HTTP server
	log.Println("Starting HTTP server on port 8080...")
	err = http.ListenAndServe(":8080", nil) // Use HTTP instead of HTTPS
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
