#!/bin/bash

# PS-02 Docker Submission - Quick Start Script
# Phishing Detection System for Critical Sector Entities

echo "🚀 PS-02 Phishing Detection System - Quick Start"
echo "=================================================="
echo ""

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Check system resources
echo "🔍 Checking system resources..."
TOTAL_RAM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
if [ $TOTAL_RAM -lt 8000 ]; then
    echo "⚠️  Warning: System has ${TOTAL_RAM}MB RAM. Recommended: 8GB+"
    echo "   The system may run slowly with less than 8GB RAM."
fi

echo "✅ System resources check complete"
echo ""

# Start the system
echo "🐳 Starting Docker containers..."
docker compose up -d

if [ $? -ne 0 ]; then
    echo "❌ Failed to start containers. Please check Docker logs."
    exit 1
fi

echo "✅ Containers started successfully"
echo ""

# Wait for services to be ready
echo "⏳ Waiting for services to initialize (this may take 2-3 minutes)..."
sleep 30

# Check container status
echo "📊 Checking container status..."
docker compose ps

echo ""
echo "🌐 System Access Points:"
echo "   Frontend Dashboard: http://localhost:3002"
echo "   Backend API:        http://localhost:8001"
echo "   API Documentation:  http://localhost:8001/docs"
echo ""

# Test API connectivity
echo "🔍 Testing API connectivity..."
if curl -s http://localhost:8001/api/stats > /dev/null; then
    echo "✅ Backend API is responding"
else
    echo "⚠️  Backend API is not responding yet. Please wait a moment and try again."
fi

if curl -s http://localhost:3002 > /dev/null; then
    echo "✅ Frontend is responding"
else
    echo "⚠️  Frontend is not responding yet. Please wait a moment and try again."
fi

echo ""
echo "🎉 Setup Complete!"
echo ""
echo "📋 Next Steps:"
echo "   1. Open your browser and go to: http://localhost:3002"
echo "   2. Explore the dashboard interface"
echo "   3. Add your CSE domains in CSE Manager"
echo "   4. Test phishing detection with suspicious domains"
echo ""
echo "🛠️  Useful Commands:"
echo "   View logs:        docker compose logs -f"
echo "   Stop system:      docker compose down"
echo "   Restart system:   docker compose restart"
echo "   Check status:     docker compose ps"
echo ""
echo "📖 For detailed instructions, see: DOCKER_SUBMISSION_README.md"
echo ""
echo "🎯 Ready for evaluation!"
