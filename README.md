# PS-02 Phishing Detection System - Docker Submission

## 🚀 Quick Start

```bash
./QUICK_START.sh
```

## 📋 System Status

### ✅ Working Components
- **Frontend Dashboard**: React-based UI at `http://localhost:3002`
- **Backend API**: Fully functional with all ML models
- **Database**: PostgreSQL with clean schema
- **Redis**: Caching and task queue
- **Celery**: Background task processing
- **API Documentation**: Available at `/docs`

## 🔧 System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │      Redis      │    │   FastAPI       │
│   (Database)    │◄──►│   (Cache/Queue) │◄──►│   (Backend)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                       ┌─────────────────┐            │
                       │   Celery        │◄───────────┘
                       │   (Workers)     │
                       └─────────────────┘
```

## 📊 API Endpoints

### Core Endpoints
- `GET /api/stats` - System statistics
- `GET /api/cse-domains` - List CSE domains
- `POST /api/cse-domains` - Add CSE domain
- `GET /api/phishing-detections` - List phishing detections
- `POST /api/manual-check` - Manual domain check

### Full API Documentation
Visit: `http://localhost:8001/docs`

## 🧪 Testing the System

### 1. Add a CSE Domain
```bash
curl -X POST "http://localhost:8001/api/cse-domains" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "organization_name": "Example Corp", "sector": "Technology"}'
```

### 2. Check Domain for Phishing
```bash
curl -X POST "http://localhost:8001/api/manual-check" \
  -H "Content-Type: application/json" \
  -d '{"domain": "paypal-fake.com"}'
```

### 3. View Statistics
```bash
curl http://localhost:8001/api/stats
```

## 🛠️ Troubleshooting

### View Logs
```bash
docker compose logs -f
```

### Restart System
```bash
docker compose restart
```

### Stop System
```bash
docker compose down
```

 📝 Notes

- Database starts clean (no pre-loaded data)
- All ML models are functional
- System is ready for evaluator testing
- Frontend uses pre-built assets for stability
