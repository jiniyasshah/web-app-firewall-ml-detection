package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"web-app-firewall-ml-detection/internal/config"
)

type EmailSender struct {
	cfg *config.Config
}

func NewEmailSender(cfg *config.Config) *EmailSender {
	return &EmailSender{cfg: cfg}
}

// BrevoRequest defines the JSON payload for the API
type BrevoRequest struct {
	Sender      Sender    `json:"sender"`
	To          []To      `json:"to"`
	Subject     string    `json:"subject"`
	HtmlContent string    `json:"htmlContent"`
	TextContent string    `json:"textContent"`
}

type Sender struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type To struct {
	Email string `json:"email"`
}

func (s *EmailSender) Send(to, subject, htmlBody, textBody, senderName string) error { // Added textBody param
	payload := BrevoRequest{
		Sender: Sender{
			Name:  senderName,
			Email: s.cfg.SMTPUser,
		},
		To: []To{
			{Email: to},
		},
		Subject:     subject,
		HtmlContent: htmlBody,
		TextContent: textBody, 
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal json: %v", err)
	}

	// 2. Create HTTP Request
	url := "https://api.brevo.com/v3/smtp/email"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// 3. Set Headers (Authentication)
	// We use SMTP_PASS to store the API Key
	req.Header.Set("accept", "application/json")
	req.Header.Set("api-key", s.cfg.SMTPPass)
	req.Header.Set("content-type", "application/json")

	// 4. Send Request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http call failed: %v", err)
	}
	defer resp.Body.Close()

	// 5. Check Response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil // Success
	}

	return fmt.Errorf("brevo api error: status %d", resp.StatusCode)
}