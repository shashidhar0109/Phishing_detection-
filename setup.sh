#!/bin/bash

# Phishing Detection System Setup Script
echo "🚀 Setting up Phishing Detection System..."

# Check if Python 3.11+ is installed
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.11"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.11+ is required. Current version: $python_version"
    exit 1
fi

echo "Success: Python version check passed: $python_version"

# Create virtual environment
echo " Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo " Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo " Installing Python dependencies..."
pip install -r requirements.txt

# Install Playwright browsers
echo " Installing Playwright browsers..."
playwright install chromium

# Create necessary directories
echo " Creating directories..."
mkdir -p logs
mkdir -p screenshots
mkdir -p reports
mkdir -p evidences
mkdir -p ps02_submissions

# Copy environment file
if [ ! -f .env ]; then
    echo "⚙️ Creating .env file..."
    cp env.example .env
    echo " .env file created. Please edit it with your configuration."
else
    echo " .env file already exists"
fi

# Install frontend dependencies
echo " Installing frontend dependencies..."
cd frontend
npm install
cd ..

# Set permissions
echo " Setting permissions..."
chmod +x start-*.sh
chmod +x stop-all.sh

echo ""
echo " Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your database and Redis configuration"
echo "2. Start PostgreSQL and Redis services"
echo "3. Run: ./start-backend.sh"
echo "4. Run: ./start-frontend.sh"
echo ""
echo "For more information, see README.md"
