# Gateway Service Structure

This document describes the structure and organization of the gateway service codebase.

## Directory Structure

```
gateway/
├── cmd/
│   └── server/          # Application entry point
│       └── main.go      # Server bootstrap and configuration
├── internal/            # Private application code
│   ├── api/            # HTTP API handlers
│   │   ├── api.go      # Main API handler struct and initialization
│   │   ├── auth.go     # Authentication endpoints
│   │   ├── dns.go      # DNS record management endpoints
│   │   ├── domains.go  # Domain management endpoints
│   │   ├── logs.go     # Log management endpoints
│   │   ├── rules.go    # WAF rules management endpoints
│   │   ├── system.go   # System status endpoints
│   │   └── waf.go      # WAF request processing handler
│   ├── database/       # Database layer
│   │   ├── mongo.go    # MongoDB operations
│   │   └── dns.go      # PowerDNS (MySQL) operations
│   ├── detector/       # WAF detection engine
│   │   ├── models.go   # Data models
│   │   ├── engine.go   # Rule engine
│   │   ├── ml.go       # ML integration
│   │   └── decision_maker.go
│   ├── limiter/        # Rate limiting
│   ├── logger/         # Logging utilities
│   ├── router/         # Route configuration
│   │   └── router.go   # Centralized route setup
│   └── service/        # Business logic layer
│       └── auth/       # Authentication service
│           └── service.go
└── pkg/                # Public packages (can be imported by other projects)
    ├── config/         # Configuration management
    │   └── config.go   # Environment-based config
    ├── middleware/     # HTTP middleware
    │   ├── auth.go     # JWT authentication middleware
    │   ├── cors.go     # CORS middleware
    │   └── logger.go   # Request logging middleware
    ├── response/       # Standardized API responses
    │   └── response.go # Success/Error response helpers
    └── validator/      # Input validation
        └── validator.go # Common validation functions
```

## Key Concepts

### Layered Architecture

The application follows a clean layered architecture:

1. **Handler Layer** (`internal/api/`): Receives HTTP requests, validates input, calls services
2. **Service Layer** (`internal/service/`): Contains business logic, orchestrates operations
3. **Database Layer** (`internal/database/`): Handles data persistence
4. **Utilities** (`pkg/`): Reusable packages for common operations

### Response Format

All API responses follow a standardized format using the `pkg/response` package:

**Success Response:**
```json
{
  "status": "success",
  "message": "Operation completed",
  "data": { ... }
}
```

**Error Response:**
```json
{
  "status": "error",
  "message": "Error description",
  "error": "Error description"
}
```

### Middleware Chain

Middleware is composable and applied in the following order:
1. CORS middleware (handles cross-origin requests)
2. Auth middleware (validates JWT tokens for protected routes)
3. Handler (processes the request)

### Configuration

Configuration is loaded from environment variables using the `pkg/config` package:
- `MONGO_URI`: MongoDB connection string
- `JWT_SECRET`: Secret key for JWT tokens
- `WAF_PUBLIC_IP`: Public IP of the WAF
- `ML_URL`: ML service endpoint
- And more...

## API Endpoints

### Public Endpoints
- `GET /api/status` - System health status
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/stream` - Server-sent events for real-time updates

### Protected Endpoints (Require Authentication)

#### Authentication
- `GET /api/auth/check` - Check authentication status

#### Domains
- `GET /api/domains` - List user's domains
- `POST /api/domains/add` - Add new domain
- `POST /api/domains/verify` - Verify domain ownership

#### DNS Records
- `GET /api/dns/records` - List DNS records
- `POST /api/dns/records` - Create DNS record
- `PUT /api/dns/records` - Update DNS record
- `DELETE /api/dns/records` - Delete DNS record

#### WAF Rules
- `GET /api/rules/global` - Get global WAF rules
- `GET /api/rules/custom` - Get custom WAF rules
- `POST /api/rules/custom/add` - Add custom rule
- `DELETE /api/rules/custom/delete` - Delete custom rule
- `POST /api/rules/toggle` - Enable/disable rule

#### Logs
- `GET /api/logs/secure` - Get security logs (paginated)

## Adding New Endpoints

1. Create handler method in appropriate `internal/api/*.go` file
2. Add route in `internal/router/router.go`
3. If business logic is complex, create service in `internal/service/`
4. Use `pkg/response` for consistent responses
5. Use `pkg/validator` for input validation
6. Use `pkg/middleware` for authentication/authorization

## Testing

Build the application:
```bash
cd gateway
go build -o bin/gateway ./cmd/server
```

Run tests:
```bash
go test ./...
```

## Best Practices

1. **Keep handlers thin**: Move business logic to service layer
2. **Use standard responses**: Always use `pkg/response` utilities
3. **Validate input**: Use `pkg/validator` for all user input
4. **Centralize config**: Use `pkg/config` for environment variables
5. **Type-safe context**: Use middleware helpers to extract context values
6. **Document changes**: Update this README when adding new features

## Security Considerations

1. JWT tokens are HttpOnly cookies
2. CORS is configured per environment
3. All user input is validated before processing
4. Rate limiting is applied to prevent abuse
5. SQL injection protection via prepared statements
6. XSS protection via proper output encoding
