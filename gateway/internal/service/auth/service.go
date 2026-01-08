package auth

import (
	"errors"
	"net/http"
	"os"
	"time"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/pkg/validator"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Service handles authentication business logic
type Service struct {
	client *mongo.Client
	secret []byte
}

// NewService creates a new auth service
func NewService(client *mongo.Client, jwtSecret string) *Service {
	return &Service{
		client: client,
		secret: []byte(jwtSecret),
	}
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	User UserResponse `json:"user"`
}

// Validate validates registration request
func (req *RegisterRequest) Validate() error {
	if err := validator.Required(req.Name, "name"); err != nil {
		return err
	}
	if err := validator.Email(req.Email); err != nil {
		return err
	}
	if err := validator.Required(req.Password, "password"); err != nil {
		return err
	}
	if len(req.Password) < 6 {
		return errors.New("password must be at least 6 characters")
	}
	return nil
}

// Validate validates login request
func (req *LoginRequest) Validate() error {
	if err := validator.Email(req.Email); err != nil {
		return err
	}
	if err := validator.Required(req.Password, "password"); err != nil {
		return err
	}
	return nil
}

// Register creates a new user account
func (s *Service) Register(req RegisterRequest) error {
	// Validate input
	if err := req.Validate(); err != nil {
		return err
	}

	// Hash password
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to hash password")
	}

	// Create user
	user := detector.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashed),
	}

	return database.CreateUser(s.client, user)
}

// Login authenticates a user and returns token and user info
func (s *Service) Login(req LoginRequest) (string, *UserResponse, error) {
	// Validate input
	if err := req.Validate(); err != nil {
		return "", nil, err
	}

	// Get user by email
	user, err := database.GetUserByEmail(s.client, req.Email)
	if err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	// Generate JWT token
	expiration := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     expiration.Unix(),
	})

	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", nil, errors.New("failed to generate token")
	}

	userResp := &UserResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}

	return tokenString, userResp, nil
}

// GetUserInfo retrieves user information by ID
func (s *Service) GetUserInfo(userID string) (*UserResponse, error) {
	user, err := database.GetUserByID(s.client, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	return &UserResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}, nil
}

// CreateAuthCookie creates an HTTP cookie for authentication
func CreateAuthCookie(token string, isProd bool) *http.Cookie {
	expiration := time.Now().Add(24 * time.Hour)
	
	cookieDomain := ""
	if isProd {
		cookieDomain = ".minishield.tech"
	}

	return &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Expires:  expiration,
		HttpOnly: true,
		Path:     "/",
		Domain:   cookieDomain,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
}

// ClearAuthCookie creates a cookie that clears the authentication
func ClearAuthCookie() *http.Cookie {
	isProd := os.Getenv("APP_ENV") == "production"
	
	cookieDomain := ""
	if isProd {
		cookieDomain = ".minishield.tech"
	}

	return &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
		Domain:   cookieDomain,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
