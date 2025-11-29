# Domain Security API - PowerShell Setup Script
# This script sets up the development environment for the Domain Security API on Windows

Write-Host "🚀 Domain Security API - PowerShell Setup Script" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green

# Check if Python is installed
Write-Host "📋 Checking Python version..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ $pythonVersion" -ForegroundColor Green
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "❌ Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if pip is installed
Write-Host "📋 Checking pip..." -ForegroundColor Yellow
try {
    $pipVersion = pip --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ $pipVersion" -ForegroundColor Green
    } else {
        throw "pip not found"
    }
} catch {
    Write-Host "❌ pip is not installed" -ForegroundColor Red
    Write-Host "Please install pip or reinstall Python" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if Git is installed
Write-Host "📋 Checking Git..." -ForegroundColor Yellow
try {
    $gitVersion = git --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ $gitVersion" -ForegroundColor Green
    } else {
        throw "Git not found"
    }
} catch {
    Write-Host "⚠️ Git is not installed" -ForegroundColor Yellow
    Write-Host "Please install Git from https://git-scm.com/download/win" -ForegroundColor Yellow
    Write-Host "You can continue without Git if you already have the code" -ForegroundColor Yellow
}

# Create virtual environment
Write-Host "🔧 Creating virtual environment..." -ForegroundColor Yellow
if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "✅ Virtual environment created" -ForegroundColor Green
} else {
    Write-Host "✅ Virtual environment already exists" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "🔧 Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# Upgrade pip
Write-Host "⬆️ Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Create .env file if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "📝 Creating .env file..." -ForegroundColor Yellow
    Copy-Item "env.example" ".env"
    Write-Host "✅ .env file created from template" -ForegroundColor Green
    Write-Host "⚠️ Please edit .env file with your API keys if needed" -ForegroundColor Yellow
} else {
    Write-Host "✅ .env file already exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "🎉 Setup completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next steps:" -ForegroundColor Cyan
Write-Host "1. Edit .env file with your API keys (optional)" -ForegroundColor White
Write-Host "2. Activate virtual environment: venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "3. Start the API: python run.py" -ForegroundColor White
Write-Host "4. Test the API: python test_api.py" -ForegroundColor White
Write-Host "5. View documentation: http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "🐳 Or use Docker:" -ForegroundColor Cyan
Write-Host "1. Install Docker Desktop" -ForegroundColor White
Write-Host "2. Build and run: docker-compose up --build" -ForegroundColor White
Write-Host "3. View documentation: http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "📚 For more information, see README.md and SETUP_GUIDE.md" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit" 