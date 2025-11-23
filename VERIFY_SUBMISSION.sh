#!/bin/bash

echo "🔍 PS-02 Docker Submission Verification"
echo "======================================"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✅ Docker is running"

# Check if the system is running
echo ""
echo "🔍 Checking system status..."

# Check containers
if docker compose ps | grep -q "Up"; then
    echo "✅ Containers are running"
else
    echo "⚠️  No containers running. Starting system..."
    ./QUICK_START.sh
fi

# Test API endpoints
echo ""
echo "🔍 Testing API endpoints..."

# Test backend
if curl -s http://localhost:8001/api/stats > /dev/null; then
    echo "✅ Backend API is responding"
    echo "   📊 Stats: $(curl -s http://localhost:8001/api/stats | jq -r '.total_cse_domains // "N/A"') CSE domains, $(curl -s http://localhost:8001/api/stats | jq -r '.total_phishing_detected // "N/A"') detections"
else
    echo "❌ Backend API is not responding"
fi

# Test frontend
if curl -s http://localhost:3002 > /dev/null; then
    echo "✅ Frontend is responding"
else
    echo "❌ Frontend is not responding"
fi

# Test database
echo ""
echo "🔍 Testing database connectivity..."
if docker compose exec -T db psql -U postgres -d phishing_detection -c "SELECT COUNT(*) FROM cse_domains;" > /dev/null 2>&1; then
    echo "✅ Database is accessible"
else
    echo "❌ Database is not accessible"
fi

echo ""
echo "🎯 System Status Summary:"
echo "========================="
echo "Frontend:  http://localhost:3002"
echo "Backend:   http://localhost:8001"
echo "API Docs:  http://localhost:8001/docs"
echo ""
echo "📋 Ready for evaluation!"
echo ""
echo "🛠️  Useful commands:"
echo "   View logs:     docker compose logs -f"
echo "   Stop system:  docker compose down"
echo "   Restart:      docker compose restart"
echo "   Check status: docker compose ps"
