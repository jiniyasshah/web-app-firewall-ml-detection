package service

import (
	"fmt"
	"log"
	"sync"
	"time"

	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/utils"

	"go.mongodb.org/mongo-driver/mongo"
)

// AlertCooldown prevents spamming the user.
// We will only send 1 alert per domain every hour, even if 1000 attacks happen.
const AlertCooldown = 1 * time.Hour

type NotificationService struct {
	Mailer    *utils.EmailSender
	Mongo     *mongo.Client
	mu        sync.Mutex
	lastAlert map[string]time.Time
}

func NewNotificationService(mailer *utils.EmailSender, client *mongo.Client) *NotificationService {
	return &NotificationService{
		Mailer:    mailer,
		Mongo:     client,
		lastAlert: make(map[string]time.Time),
	}
}

// SendSignupVerification sends the verification link to new users.
// Sender Name: "Minishield Verification"
func (s *NotificationService) SendSignupVerification(email, name, token string) {
	subject := "Action Required: Verify your MiniShield Account"

	// [IMPORTANT] Link points to the BACKEND API first for verification
	verifyLink := fmt.Sprintf("https://api.minishield.tech/api/auth/verify?token=%s", token)

	// 1. HTML Version (Visual)
	htmlBody := fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto;">
			<div style="background-color: #f4f4f4; padding: 20px; text-align: center;">
				<h2 style="color: #333; margin:0;">Welcome to MiniShield</h2>
			</div>
			<div style="padding: 20px; border: 1px solid #ddd; border-top: none;">
				<p>Hi %s,</p>
				<p>Thank you for registering. Please click the button below to verify your email address and activate your account:</p>
				
				<div style="text-align: center; margin: 30px 0;">
					<a href="%s" style="background-color: #007bff; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">
						Verify Account
					</a>
				</div>

				<p style="font-size: 13px; color: #666;">
					Or copy and paste this link into your browser:<br>
					<a href="%s" style="color: #007bff;">%s</a>
				</p>
				
				<p>If you did not create an account, you can safely ignore this email.</p>
			</div>
		</div>
	`, name, verifyLink, verifyLink, verifyLink)

	// 2. Text Version (For Spam Filters & Apple Watch)
	textBody := fmt.Sprintf("Hi %s,\n\nWelcome to MiniShield.\n\nPlease verify your account by clicking this link:\n%s\n\nIf you did not create an account, please ignore this email.", name, verifyLink)

	// Send asynchronously
	go func() {
		// Log for debugging
		log.Printf("📧 Sending verification link to %s...", email)
		
		// [REQUIRES email.go UPDATE] We now pass htmlBody AND textBody
		if err := s.Mailer.Send(email, subject, htmlBody, textBody, "Minishield Verification"); err != nil {
			log.Printf("[EMAIL ERROR] Failed to send verification to %s: %v", email, err)
		} else {
			log.Printf("✅ Verification email sent to %s", email)
		}
	}()
}

// NotifyAttack sends a security alert if a High-Confidence attack is blocked.
// Sender Name: "Minishield Security"
func (s *NotificationService) NotifyAttack(userID, domainName, attackType, ip string) {
	// 1. Check Throttling (In-Memory)
	s.mu.Lock()
	lastTime, exists := s.lastAlert[domainName]
	if exists && time.Since(lastTime) < AlertCooldown {
		s.mu.Unlock()
		return // Throttled: Do not send email
	}
	s.lastAlert[domainName] = time.Now()
	s.mu.Unlock()

	// 2. Run Asynchronously (Don't slow down the WAF)
	go func() {
		// A. Lookup User Email
		user, err := database.GetUserByID(s.Mongo, userID)
		if err != nil {
			log.Printf("[EMAIL ERROR] Could not find user %s for alert: %v", userID, err)
			return
		}

		// B. Prepare Email Content
		subject := fmt.Sprintf("🚨 Security Alert: Attack blocked on %s", domainName)
		
		// HTML Version
		htmlBody := fmt.Sprintf(`
			<div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; border: 1px solid #d32f2f;">
				<div style="background-color: #d32f2f; padding: 15px; text-align: center;">
					<h2 style="color: white; margin: 0;">Malicious Activity Blocked</h2>
				</div>
				<div style="padding: 20px;">
					<p>Hello,</p>
					<p>MiniShield WAF has detected and <b>blocked</b> a high-confidence attack targeting your domain <strong>%s</strong>.</p>
					
					<table style="width: 100%%; border-collapse: collapse; margin-top: 15px;">
						<tr style="background-color: #f9f9f9;">
							<td style="padding: 10px; border: 1px solid #ddd;"><b>Attack Type</b></td>
							<td style="padding: 10px; border: 1px solid #ddd; color: #d32f2f; font-weight: bold;">%s</td>
						</tr>
						<tr>
							<td style="padding: 10px; border: 1px solid #ddd;"><b>Source IP</b></td>
							<td style="padding: 10px; border: 1px solid #ddd;">%s</td>
						</tr>
						<tr style="background-color: #f9f9f9;">
							<td style="padding: 10px; border: 1px solid #ddd;"><b>Time</b></td>
							<td style="padding: 10px; border: 1px solid #ddd;">%s</td>
						</tr>
					</table>

					<p style="margin-top: 20px;">No action is required on your part. The request was intercepted before it reached your server.</p>
					
					<hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
					<p style="font-size: 12px; color: #777;">To prevent inbox spam, we will not send another notification for this domain for at least 1 hour.</p>
				</div>
			</div>
		`, domainName, attackType, ip, time.Now().Format(time.RFC1123))

		// [NEW] Text Version (The 4th Argument)
		textBody := fmt.Sprintf("🚨 Security Alert\n\nMalicious activity blocked on %s.\n\nAttack Type: %s\nSource IP: %s\nTime: %s\n\nNo action is required.", domainName, attackType, ip, time.Now().Format(time.RFC1123))

		// C. Send Email (Pass 5 Arguments: email, subject, html, text, senderName)
		if err := s.Mailer.Send(user.Email, subject, htmlBody, textBody, "Minishield Security"); err != nil {
			log.Printf("[EMAIL ERROR] Failed to send alert to %s: %v", user.Email, err)
		} else {
			log.Printf("📧 Alert sent to %s regarding %s", user.Email, domainName)
		}
	}()
}