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
		return "", nil, errors.New("invalid credentials")
	}

	// Check Verification Status
	if !user.IsVerified {
		return "", nil, errors.New("email not verified. please check your inbox")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", nil, errors.New("invalid credentials")
	}

	expiration := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
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