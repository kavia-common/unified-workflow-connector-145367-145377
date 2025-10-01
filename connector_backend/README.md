# Connector Backend (FastAPI)

This service provides REST APIs and real-time endpoints for unified connectors (Jira, Confluence, Slack, GitHub, etc.).

## Prerequisites
- Python 3.12
- MongoDB available and reachable
- (Optional) Redis for caching / jobs

## Setup

1) Create a `.env` file based on `.env.example`:
   - SECRET_KEY: secure random string for JWT
   - ENCRYPTION_KEY: secure string used to derive encryption key
   - MONGODB_URL: e.g. mongodb://localhost:27017
   - MONGODB_DB_NAME: default is workflow_connector

2) Install dependencies:
```
python3 -m pip install -r requirements.txt
```

3) Start the server:
```
python3 start.py
```

Server configuration via env:
- HOST (default 0.0.0.0)
- PORT (default 8000)
- DEBUG (true/false, enables reload)
- LOG_LEVEL (info, debug, warning, error)
- WORKERS (number of uvicorn workers; when DEBUG=true, workers=1)

Health check:
- Basic: GET /
- Detailed: GET /health
- API routes: GET /api/v1/...

Notes:
- If you run in development without MongoDB, detailed health will show degraded/unhealthy; basic server should still start if required environment variables are set.
- Dependency pin conflict between flake8 and pycodestyle has been resolved by pinning pycodestyle==2.12.1 (compatible with flake8==7.1.1).
