package service

import (
	"errors"
	"fmt"
	"time"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	Mongo    *mongo.Client
	Cfg      *config.Config
	Notifier *NotificationService 
}

func NewAuthService(client *mongo.Client, cfg *config.Config, notifier *NotificationService) *AuthService {
	return &AuthService{
		Mongo:    client,
		Cfg:      cfg,
		Notifier: notifier,
	}
}

func (s *AuthService) Register(input models.UserInput) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), 10)
	if err != nil {
		return err
	}

	// Generate a simple token (current timestamp in nanos)
	token := fmt.Sprintf("%d", time.Now().UnixNano())

	user := models.User{
		Name:              input.Name,
		Email:             input.Email,
		Password:          string(hashed),
		IsVerified:        false, 
		VerificationToken: token, 
	}

	if err := database.CreateUser(s.Mongo, user); err != nil {
		return err
	}

	// Send Verification Email
	s.Notifier.SendSignupVerification(user.Email, user.Name, token)

	return nil
}

func (s *AuthService) Login(email, password string) (string, *models.User, error) {
	user, err := database.GetUserByEmail(s.Mongo, email)
	if err != nil {
		return "", nil, errors.New("Invalid Credentials. Please try again")
	}

	// Check Verification Status
	if !user.IsVerified {
		return "", nil, errors.New("Email not verified. Please check your inbox")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", nil, errors.New("Invalid Credentials. Please try again")
	}

	expiration := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"token_version": user.TokenVersion,
		"exp":     expiration.Unix(),
	})

	tokenString, err := token.SignedString([]byte(s.Cfg.JWTSecret))
	if err != nil {
		return "", nil, err
	}

	return tokenString, user, nil
}

// Logic to handle the click
func (s *AuthService) VerifyEmail(token string) error {
	return database.VerifyUserToken(s.Mongo, token)
}

func (s *AuthService) GetUser(userID string) (*models.User, error) {
	return database.GetUserByID(s.Mongo, userID)
}


func (s *AuthService) UpdatePassword(userID, oldPassword, newPassword string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return errors.New("incorrect current password")
	}

	// Hash new password
	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return err
	}

	if err := database.UpdateUserPassword(s.Mongo, userID, string(hashed)); err != nil {
		return err
	}

	s.Notifier.SendPasswordChangedNotification(user.Email, user.Name)
	return nil
}

func (s *AuthService) ForgotPassword(email string) error {
	user, err := database.GetUserByEmail(s.Mongo, email)
	if err != nil {
		// Return nil to prevent email enumeration attacks (don't reveal if email exists)
		return nil 
	}

	// Generate a simple token (in production, use crypto/rand)
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	expiry := time.Now().Add(1 * time.Hour).Unix() // 1 hour expiration

	if err := database.SetPasswordResetToken(s.Mongo, email, token, expiry); err != nil {
		return err
	}

	s.Notifier.SendPasswordResetEmail(user.Email, user.Name, token)
	return nil
}

func (s *AuthService) ResetPassword(token, newPassword string) error {
	user, err := database.GetUserByResetToken(s.Mongo, token)
	if err != nil {
		return err
	}

	// Check if token expired
	if time.Now().Unix() > user.ResetTokenExpiry {
		return errors.New("reset token has expired")
	}

	// Hash new password
	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return err
	}

	// Update password and clear token
	if err := database.UpdateUserPassword(s.Mongo, user.ID, string(hashed)); err != nil {
		return err
	}
	_ = database.ClearPasswordResetToken(s.Mongo, user.ID)

	s.Notifier.SendPasswordChangedNotification(user.Email, user.Name)
	return nil
}

func (s *AuthService) RequestEmailChange(userID, newEmail string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return errors.New("user not found")
	}

	if user.Email == newEmail {
		return errors.New("this is already your current email address")
	}

	// Generate token
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	expiry := time.Now().Add(1 * time.Hour).Unix()

	// Save to DB
	if err := database.SetPendingEmail(s.Mongo, userID, newEmail, token, expiry); err != nil {
		return err
	}

	// Send to NEW email
	s.Notifier.SendEmailChangeVerification(newEmail, user.Name, token)
	return nil
}

func (s *AuthService) VerifyEmailChange(token string) error {
	user, err := database.GetUserByEmailChangeToken(s.Mongo, token)
	if err != nil {
		return err
	}

	if time.Now().Unix() > user.EmailChangeTokenExpiry {
		return errors.New("verification link has expired")
	}

	oldEmail := user.Email
	newEmail := user.PendingEmail

	// Apply change
	if err := database.ConfirmEmailChange(s.Mongo, user.ID, newEmail); err != nil {
		return err
	}

	// Notify OLD email about the successful change
	s.Notifier.SendEmailChangedNotification(oldEmail, newEmail, user.Name)
	return nil
}