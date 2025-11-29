@echo off
REM Domain Security API - Windows Setup Script
REM This script sets up the development environment for the Domain Security API on Windows

echo 🚀 Domain Security API - Windows Setup Script
echo ==============================================

REM Check if Python is installed
echo 📋 Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

python --version
echo ✅ Python is installed

REM Check if pip is installed
echo 📋 Checking pip...
pip --version >nul 2>&1
if errorlevel 1 (
    echo ❌ pip is not installed
    echo Please install pip or reinstall Python
    pause
    exit /b 1
)

echo ✅ pip is installed

REM Check if Git is installed
echo 📋 Checking Git...
git --version >nul 2>&1
if errorlevel 1 (
    echo ⚠️ Git is not installed
    echo Please install Git from https://git-scm.com/download/win
    echo You can continue without Git if you already have the code
)

REM Create virtual environment
echo 🔧 Creating virtual environment...
if not exist "venv" (
    python -m venv venv
    echo ✅ Virtual environment created
) else (
    echo ✅ Virtual environment already exists
)

REM Activate virtual environment
echo 🔧 Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo ⬆️ Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo 📦 Installing dependencies...
pip install -r requirements.txt

REM Create .env file if it doesn't exist
if not exist ".env" (
    echo 📝 Creating .env file...
    copy env.example .env
    echo ✅ .env file created from template
    echo ⚠️ Please edit .env file with your API keys if needed
) else (
    echo ✅ .env file already exists
)

echo.
echo 🎉 Setup completed successfully!
echo.
echo 📋 Next steps:
echo 1. Edit .env file with your API keys (optional)
echo 2. Activate virtual environment: venv\Scripts\activate
echo 3. Start the API: python run.py
echo 4. Test the API: python test_api.py
echo 5. View documentation: http://localhost:8000/docs
echo.
echo 🐳 Or use Docker:
echo 1. Install Docker Desktop
echo 2. Build and run: docker-compose up --build
echo 3. View documentation: http://localhost:8000/docs
echo.
echo 📚 For more information, see README.md and SETUP_GUIDE.md
echo.
pause 