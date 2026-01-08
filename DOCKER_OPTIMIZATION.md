# Docker Composition Optimization

## Changes Made

### 1. Certificate Volume Persistence
**Problem**: Using a bind mount (`./certs:/app/certs`) means certificates are stored locally and can be lost if the folder is cleaned up, leading to Let's Encrypt rate limits.

**Solution**: Changed to a named Docker volume:
```yaml
volumes:
  - certs_volume:/app/certs
```

**Benefits**:
- Certificates persist even if local `certs/` directory is deleted
- Avoids Let's Encrypt rate limits when recreating containers
- Certificates are managed by Docker and survive container recreation

### 2. Environment Variables Configuration
**Created**: `.env.example` file with all required environment variables

**Usage**:
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Update the values in `.env` with your actual configuration:
   - `MONGO_URI`: Your MongoDB connection string
   - `FRONTEND_URL`: Your frontend application URL
   - `WAF_PUBLIC_IP`: Your server's public IP address
3. Docker Compose will automatically load variables from `.env` file

### 3. ML Scorer Service Cleanup
**Changes**:
- Replaced all `print()` statements with proper Python `logging`
- Added structured logging with timestamps and log levels
- Removed emoji-heavy debug output
- Changed log levels appropriately:
  - `logger.info()` for informational messages
  - `logger.error()` for critical errors
  - `logger.warning()` for warnings
  - `logger.debug()` for detailed debugging

**Benefits**:
- Professional, production-ready logging
- Easier log aggregation and analysis
- Better compatibility with log management systems
- Cleaner console output
- Configurable log levels

### 4. Docker Compose Format
**Note**: The docker-compose.yml already uses the modern format without a version field, which is the recommended approach for Docker Compose v2+.

## How to Use

### First Time Setup
```bash
# 1. Copy environment file
cp .env.example .env

# 2. Edit .env with your values
nano .env  # or use your preferred editor

# 3. Build and start services
docker compose build
docker compose up
```

### Certificate Management
The certificates are now stored in a Docker volume named `certs_volume`. To manage it:

```bash
# List volumes
docker volume ls

# Inspect certificate volume
docker volume inspect sanku_certs_volume

# Backup certificates (if needed)
docker run --rm -v sanku_certs_volume:/certs -v $(pwd)/backup:/backup alpine tar czf /backup/certs-backup.tar.gz -C /certs .

# Restore certificates (if needed)
docker run --rm -v sanku_certs_volume:/certs -v $(pwd)/backup:/backup alpine tar xzf /backup/certs-backup.tar.gz -C /certs
```

## ML Scorer Logging Examples

Before (with emojis and print statements):
```
⚠️ Model not found. Training...
📂 Loading Payload Data...
✅ Loaded 1000 total samples.
```

After (with structured logging):
```
2026-01-08 14:17:00 - __main__ - INFO - Model not found. Training...
2026-01-08 14:17:01 - __main__ - INFO - Loading Payload Data...
2026-01-08 14:17:02 - __main__ - INFO - Loaded 1000 total samples.
```

## Troubleshooting

### If certificates are lost
With the new volume-based approach, certificates persist across container recreations. However, if you need to clean everything and start fresh:

```bash
# Stop containers
docker compose down

# Remove the certificate volume (WARNING: This will delete certificates)
docker volume rm sanku_certs_volume

# Start fresh
docker compose up
```

### Viewing logs
```bash
# View ml_scorer logs
docker compose logs -f ml_scorer

# View all service logs
docker compose logs -f
```

### Checking certificate volume location
```bash
docker volume inspect sanku_certs_volume
```

Look for the `Mountpoint` field to see where Docker stores the volume data on the host.
