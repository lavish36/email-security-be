# 🚀 Domain Security API - Complete Setup Guide

A comprehensive guide to set up the Domain Security API on any system (Windows, macOS, Linux).

## 📋 Prerequisites

### System Requirements
- **Python**: 3.8 or higher
- **RAM**: Minimum 512MB (1GB recommended)
- **Storage**: 100MB free space
- **Network**: Internet connection for dependency installation

### Required Software
- Python 3.8+
- pip (Python package installer)
- Git (for cloning the repository)

## 🎯 Understanding the Scoring System

The Domain Security API uses an **industry-standard scoring system** that aligns with professional security tools like Easy DMARC. Our 100-point evaluation focuses on the three core protocols essential for email security:

### Core Protocols (70 points)
- **SPF**: 25 points - Sender Policy Framework validation
- **DKIM**: 25 points - DomainKeys Identified Mail validation  
- **DMARC**: 20 points - Domain-based Message Authentication validation

### Policy Enforcement (20 points)
- **DMARC Policy**: 15 points - How strictly policies are enforced
- **SPF Hygiene**: 5 points - Security mechanism validation

### Advanced Features (10 points)
- **MTA-STS**: 4 points - Mail Transfer Agent Strict Transport Security
- **TLS-RPT**: 3 points - TLS Reporting
- **BIMI**: 3 points - Brand Indicators for Message Identification

### Risk Levels
- **90-100**: Low Risk (Excellent security posture)
- **70-89**: Medium Risk (Good security with room for improvement)
- **0-69**: High Risk (Critical security issues)

For detailed scoring information, see [Domain_Security_Scoring_System_Documentation.md](Domain_Security_Scoring_System_Documentation.md).

---

## 🖥️ Operating System Specific Setup

### Windows Setup

#### 1. Install Python
1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run the installer with **"Add Python to PATH"** checked
3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

#### 2. Install Git
1. Download Git from [git-scm.com](https://git-scm.com/download/win)
2. Run the installer with default settings
3. Verify installation:
   ```cmd
   git --version
   ```

#### 3. Clone and Setup
```cmd
# Clone the repository
git clone <repository-url>
cd email-repo

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
copy env.example .env
```

### macOS Setup

#### 1. Install Python
**Option A: Using Homebrew (Recommended)**
```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python

# Verify installation
python3 --version
pip3 --version
```

**Option B: Using Official Installer**
1. Download from [python.org](https://www.python.org/downloads/macos/)
2. Run the installer
3. Verify installation

#### 2. Install Git
```bash
# Using Homebrew
brew install git

# Or download from git-scm.com
```

#### 3. Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd email-repo

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp env.example .env
```

### Linux Setup (Ubuntu/Debian)

#### 1. Install Python and Git
```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install Git
sudo apt install git

# Verify installations
python3 --version
pip3 --version
git --version
```

#### 2. Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd email-repo

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp env.example .env
```

### Linux Setup (CentOS/RHEL/Fedora)

#### 1. Install Python and Git
```bash
# CentOS/RHEL
sudo yum install python3 python3-pip git

# Fedora
sudo dnf install python3 python3-pip git

# Verify installations
python3 --version
pip3 --version
git --version
```

#### 2. Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd email-repo

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp env.example .env
```

---

## 🐳 Docker Setup (Alternative)

### Prerequisites
- Docker Desktop installed
- Docker Compose installed

### Quick Docker Setup
```bash
# Clone the repository
git clone <repository-url>
cd email-repo

# Build and run with Docker Compose
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

### Manual Docker Setup
```bash
# Build the Docker image
docker build -t domain-security-api .

# Run the container
docker run -p 8000:8000 domain-security-api
```

---

## ⚙️ Configuration

### 1. Environment Variables
Edit the `.env` file with your configuration:

```env
# API Configuration
API_TITLE=Domain Security API
API_VERSION=1.0.0
DEBUG=True

# External API Keys (Optional - for enhanced features)
IPINFO_TOKEN=your_ipinfo_token
VIRUSTOTAL_API_KEY=your_virustotal_key
SPAMHAUS_API_KEY=your_spamhaus_key

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60

# Server Configuration
HOST=0.0.0.0
PORT=8000
```

### 2. Optional API Keys Setup
For enhanced features, obtain API keys from:
- **IPInfo**: [ipinfo.io](https://ipinfo.io/) - For geolocation data
- **VirusTotal**: [virustotal.com](https://virustotal.com/) - For threat intelligence
- **Spamhaus**: [spamhaus.org](https://spamhaus.org/) - For blacklist checking

---

## 🚀 Running the Application

### Development Mode
```bash
# Activate virtual environment (if not already activated)
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Run the application
python run.py
```

### Production Mode
```bash
# Using uvicorn directly
uvicorn app.main:app --host 0.0.0.0 --port 8000

# With workers (for production)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Using the Setup Script (macOS/Linux)
```bash
# Make the script executable
chmod +x setup.sh

# Run the setup script
./setup.sh
```

---

## 🧪 Testing the Installation

### 1. Check API Health
```bash
# Using curl
curl http://localhost:8000/health

# Using Python
python test_api.py
```

### 2. Access API Documentation
Open your browser and visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 3. Test Basic Endpoints
```bash
# Test domain security scan
curl "http://localhost:8000/api/v1/security/scan/example.com"

# Test SPF check
curl "http://localhost:8000/api/v1/security/spf/example.com"
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Python Version Issues
```bash
# Check Python version
python --version
python3 --version

# If multiple Python versions, use specific version
python3.8 -m venv venv
```

#### 2. Virtual Environment Issues
```bash
# Delete and recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

#### 3. Port Already in Use
```bash
# Check what's using port 8000
# Windows:
netstat -ano | findstr :8000
# macOS/Linux:
lsof -i :8000

# Kill the process or change port in .env file
```

#### 4. Permission Issues (Linux/macOS)
```bash
# Fix permissions
chmod +x setup.sh
chmod +x run.py
chmod +x test_api.py
```

#### 5. Network/Firewall Issues
- Ensure port 8000 is open
- Check firewall settings
- Try using `127.0.0.1` instead of `0.0.0.0`

### Dependency Issues

#### 1. SSL Certificate Issues
```bash
# Upgrade pip and setuptools
pip install --upgrade pip setuptools wheel

# Install with trusted host (if needed)
pip install -r requirements.txt --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

#### 2. Compilation Issues (Windows)
```bash
# Install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
```

---

## 📚 Next Steps

### 1. Explore the API
- Visit http://localhost:8000/docs
- Try different endpoints
- Test with your own domains

### 2. Customize Configuration
- Edit `.env` file for your needs
- Add API keys for enhanced features
- Configure rate limiting

### 3. Development
- Check out the project structure
- Review the codebase
- Contribute to the project

### 4. Production Deployment
- Set `DEBUG=False` in production
- Configure proper logging
- Set up reverse proxy (nginx)
- Use process manager (systemd, PM2)

---

## 🆘 Getting Help

### Documentation
- [API Documentation](http://localhost:8000/docs) - Interactive API documentation
- [README.md](README.md) - Project overview and features
- [QUICK_SETUP.md](QUICK_SETUP.md) - Quick reference commands

### Support Channels
- Create an issue on GitHub
- Check existing issues and discussions
- Review the troubleshooting section above

### Community
- Join our Discord/Slack community
- Follow us on social media
- Subscribe to our newsletter

---

## ✅ Verification Checklist

- [ ] Python 3.8+ installed and working
- [ ] Git installed and working
- [ ] Repository cloned successfully
- [ ] Virtual environment created and activated
- [ ] Dependencies installed without errors
- [ ] Environment file configured
- [ ] Application starts without errors
- [ ] API documentation accessible
- [ ] Basic endpoints responding
- [ ] Optional API keys configured (if needed)

---

**🎉 Congratulations!** You've successfully set up the Domain Security API. The application is now ready to use for comprehensive domain security scanning and analysis. 