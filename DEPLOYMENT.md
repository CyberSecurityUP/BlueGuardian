# BlueGuardian AI - Deployment Guide

Complete deployment guide for BlueGuardian AI security analysis framework.

## Table of Contents

1. [Quick Start with Docker Compose](#quick-start-with-docker-compose)
2. [Manual Deployment](#manual-deployment)
3. [Production Deployment](#production-deployment)
4. [Configuration](#configuration)
5. [Troubleshooting](#troubleshooting)

## Quick Start with Docker Compose

The easiest way to run BlueGuardian AI is using Docker Compose.

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- At least one AI provider API key (Claude, OpenAI, or Gemini)

### Steps

1. **Clone the repository**

```bash
git clone https://github.com/your-org/blueguardian-ai.git
cd blueguardian-ai
```

2. **Configure environment variables**

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```bash
# Required: At least one AI provider
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here

# Optional: Threat Intelligence
VIRUSTOTAL_API_KEY=your-vt-key-here
HYBRID_ANALYSIS_API_KEY=your-ha-key-here
OTX_API_KEY=your-otx-key-here

# Multi-model consensus (recommended)
ENABLE_MULTI_MODEL_CONSENSUS=true
CONSENSUS_PROVIDERS=claude,openai

# SIEM Integration (optional)
ENABLE_SIEM_INTEGRATION=false
SIEM_TYPE=splunk
SPLUNK_HEC_TOKEN=your-token-here
SPLUNK_HEC_URL=https://your-splunk:8088
```

3. **Start all services**

```bash
docker-compose up -d
```

This will start:
- **Backend API** on `http://localhost:8000`
- **Web UI** on `http://localhost:3000`
- **Sandbox** (isolated container for malware analysis)

4. **Verify deployment**

```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Test API
curl http://localhost:8000/api/v1/health
```

5. **Access the Web UI**

Open your browser and navigate to `http://localhost:3000`

## Manual Deployment

For development or custom deployments without Docker.

### Backend Setup

1. **Install Python dependencies**

```bash
# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env with your API keys
```

2. **Run the API server**

```bash
# Development mode
uvicorn src.interfaces.api_server:app --reload --host 0.0.0.0 --port 8000

# Production mode (with gunicorn)
gunicorn src.interfaces.api_server:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Frontend Setup

1. **Install Node.js dependencies**

```bash
cd frontend
npm install

# Copy environment configuration
cp .env.example .env
```

2. **Run development server**

```bash
npm run dev
```

Access at `http://localhost:3000`

3. **Build for production**

```bash
npm run build

# Serve with a static file server
npm install -g serve
serve -s dist -l 3000
```

## Production Deployment

### Using Nginx (Recommended)

1. **Backend with Systemd**

Create `/etc/systemd/system/blueguardian-api.service`:

```ini
[Unit]
Description=BlueGuardian AI API
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/blueguardian-ai
Environment="PATH=/opt/blueguardian-ai/venv/bin"
EnvironmentFile=/opt/blueguardian-ai/.env
ExecStart=/opt/blueguardian-ai/venv/bin/gunicorn \
    src.interfaces.api_server:app \
    -w 4 \
    -k uvicorn.workers.UvicornWorker \
    --bind unix:/run/blueguardian-api.sock \
    --access-logfile /var/log/blueguardian/access.log \
    --error-logfile /var/log/blueguardian/error.log

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable blueguardian-api
sudo systemctl start blueguardian-api
sudo systemctl status blueguardian-api
```

2. **Nginx Configuration**

Create `/etc/nginx/sites-available/blueguardian`:

```nginx
# Backend API
upstream blueguardian_backend {
    server unix:/run/blueguardian-api.sock fail_timeout=0;
}

server {
    listen 80;
    server_name api.blueguardian.example.com;

    # SSL configuration (recommended)
    # listen 443 ssl http2;
    # ssl_certificate /etc/letsencrypt/live/api.blueguardian.example.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/api.blueguardian.example.com/privkey.pem;

    client_max_body_size 100M;

    location / {
        proxy_pass http://blueguardian_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
}

# Frontend
server {
    listen 80;
    server_name blueguardian.example.com;

    # SSL configuration (recommended)
    # listen 443 ssl http2;
    # ssl_certificate /etc/letsencrypt/live/blueguardian.example.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/blueguardian.example.com/privkey.pem;

    root /var/www/blueguardian-frontend/dist;
    index index.html;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Proxy API requests
    location /api/ {
        proxy_pass http://blueguardian_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and reload Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/blueguardian /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Using Kubernetes

Example Kubernetes manifests:

**backend-deployment.yaml**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blueguardian-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: blueguardian-backend
  template:
    metadata:
      labels:
        app: blueguardian-backend
    spec:
      containers:
      - name: api
        image: blueguardian-ai:latest
        ports:
        - containerPort: 8000
        env:
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: blueguardian-secrets
              key: anthropic-api-key
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: blueguardian-secrets
              key: openai-api-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
---
apiVersion: v1
kind: Service
metadata:
  name: blueguardian-backend
spec:
  selector:
    app: blueguardian-backend
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP
```

**frontend-deployment.yaml**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blueguardian-frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: blueguardian-frontend
  template:
    metadata:
      labels:
        app: blueguardian-frontend
    spec:
      containers:
      - name: nginx
        image: blueguardian-frontend:latest
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: blueguardian-frontend
spec:
  selector:
    app: blueguardian-frontend
  ports:
  - port: 80
    targetPort: 80
  type: LoadBalancer
```

Apply manifests:

```bash
kubectl create secret generic blueguardian-secrets \
  --from-literal=anthropic-api-key=your-key \
  --from-literal=openai-api-key=your-key

kubectl apply -f backend-deployment.yaml
kubectl apply -f frontend-deployment.yaml
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key | Yes* | - |
| `OPENAI_API_KEY` | OpenAI API key | Yes* | - |
| `GOOGLE_API_KEY` | Google Gemini API key | No | - |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | No | - |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis API key | No | - |
| `OTX_API_KEY` | AlienVault OTX API key | No | - |
| `ENABLE_MULTI_MODEL_CONSENSUS` | Enable consensus mode | No | `true` |
| `CONSENSUS_PROVIDERS` | Comma-separated provider list | No | `claude,openai` |
| `ENABLE_SIEM_INTEGRATION` | Enable SIEM integration | No | `false` |
| `SIEM_TYPE` | SIEM platform type | No | `splunk` |
| `SPLUNK_HEC_TOKEN` | Splunk HEC token | No | - |
| `SPLUNK_HEC_URL` | Splunk HEC URL | No | - |
| `ELASTICSEARCH_URL` | Elasticsearch URL | No | - |

*At least one AI provider is required

### Resource Requirements

**Minimum (Development)**
- CPU: 2 cores
- RAM: 4 GB
- Disk: 10 GB

**Recommended (Production)**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 50 GB (for logs and reports)

**High-Volume Production**
- CPU: 8+ cores
- RAM: 16+ GB
- Disk: 100+ GB SSD
- Load balancer for multiple instances

## Troubleshooting

### Backend Issues

**API not starting**

```bash
# Check logs
docker-compose logs backend

# Or for manual deployment
tail -f /var/log/blueguardian/error.log

# Common issues:
# - Missing API keys in .env
# - Port 8000 already in use
# - Python dependencies not installed
```

**High memory usage**

```bash
# Reduce number of worker processes
# In docker-compose.yml or systemd service:
gunicorn ... -w 2  # Instead of -w 4
```

**AI provider errors**

```bash
# Test API keys
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-5-20250929","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'

# Check consensus configuration
# Make sure CONSENSUS_PROVIDERS includes only configured providers
```

### Frontend Issues

**Blank page**

```bash
# Check browser console for errors
# Common issues:
# - VITE_API_URL not set correctly
# - Backend not reachable
# - CORS issues

# Fix CORS by ensuring backend allows origin:
# In src/interfaces/api_server.py, check CORS middleware configuration
```

**API requests failing**

```bash
# Check network tab in browser dev tools
# Ensure backend is reachable

# Test backend directly
curl http://localhost:8000/api/v1/health
```

### Docker Issues

**Services not starting**

```bash
# Check service status
docker-compose ps

# View logs for specific service
docker-compose logs -f backend

# Rebuild images
docker-compose build --no-cache
docker-compose up -d
```

**Permission errors**

```bash
# Fix volume permissions
sudo chown -R $USER:$USER uploads reports data
```

### Performance Optimization

**Slow analysis**

- Enable multi-model consensus with faster models
- Use local Ollama for some analyses
- Implement caching for repeated analyses
- Scale horizontally with multiple backend instances

**High API costs**

- Monitor costs via `/api/v1/costs` endpoint
- Use cheaper models for initial triage
- Implement request throttling
- Cache threat intelligence lookups

## Monitoring

### Logging

Logs are stored in:
- Docker: `docker-compose logs`
- Manual: `/var/log/blueguardian/`

### Metrics

Monitor these metrics:
- Analysis queue length
- Average analysis time
- API cost per analysis
- Error rate
- Memory/CPU usage

### Health Checks

```bash
# API health
curl http://localhost:8000/api/v1/health

# System status
curl http://localhost:8000/api/v1/status

# Cost tracking
curl http://localhost:8000/api/v1/costs
```

## Security Best Practices

1. **API Keys**: Never commit `.env` files, use secrets management
2. **Network**: Run sandbox in isolated network
3. **TLS**: Use HTTPS in production (Let's Encrypt)
4. **Authentication**: Add auth layer for production API
5. **Firewall**: Restrict access to API endpoints
6. **Updates**: Regularly update dependencies
7. **Backups**: Backup analysis results and configurations

## Support

For deployment issues:
- Check [GitHub Issues](https://github.com/your-org/blueguardian-ai/issues)
- Join [Discord Community](https://discord.gg/blueguardian)
- Read [Documentation](https://blueguardian-ai.readthedocs.io)
