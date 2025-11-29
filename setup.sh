#!/bin/bash

# Domain Security API - Setup Script
# This script sets up the development environment for the Domain Security API

set -e

echo "🚀 Domain Security API - Setup Script"
echo "======================================"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Python 3.8+ is installed
echo "📋 Checking Python version..."
if command_exists python3; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
    required_version="3.8"
    
    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
        echo "✅ Python $python_version is installed"
    else
        echo "❌ Python 3.8+ is required. Current version: $python_version"
        echo "Please install Python 3.8+ from https://www.python.org/downloads/"
        exit 1
    fi
elif command_exists python; then
    python_version=$(python --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
    required_version="3.8"
    
    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
        echo "✅ Python $python_version is installed"
    else
        echo "❌ Python 3.8+ is required. Current version: $python_version"
        echo "Please install Python 3.8+ from https://www.python.org/downloads/"
        exit 1
    fi
else
    echo "❌ Python is not installed"
    echo "Please install Python 3.8+ from https://www.python.org/downloads/"
    exit 1
fi

# Check if pip is installed
if command_exists pip3; then
    echo "✅ pip3 is installed"
elif command_exists pip; then
    echo "✅ pip is installed"
else
    echo "❌ pip is not installed. Please install pip first."
    echo "You can install pip by running: python -m ensurepip --upgrade"
    exit 1
fi

# Check if Git is installed
echo "📋 Checking Git..."
if command_exists git; then
    echo "✅ Git is installed"
else
    echo "⚠️ Git is not installed"
    echo "Please install Git from https://git-scm.com/downloads"
    echo "You can continue without Git if you already have the code"
fi

# Create virtual environment
echo "🔧 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file..."
    cp env.example .env
    echo "✅ .env file created from template"
    echo "⚠️ Please edit .env file with your API keys if needed"
else
    echo "✅ .env file already exists"
fi

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x run.py
chmod +x test_api.py

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file with your API keys (optional)"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Start the API: python run.py"
echo "4. Test the API: python test_api.py"
echo "5. View documentation: http://localhost:8000/docs"
echo ""
echo "🐳 Or use Docker:"
echo "1. Build and run: docker-compose up --build"
echo "2. View documentation: http://localhost:8000/docs"
echo ""
echo "📚 For more information, see README.md" 