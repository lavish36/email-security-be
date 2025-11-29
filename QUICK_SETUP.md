# ⚡ Quick Setup Reference

## 🚀 One-Command Setup

### Windows
```cmd
# Batch script
setup.bat

# PowerShell script
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### macOS/Linux
```bash
# Bash script
chmod +x setup.sh && ./setup.sh
```

### Docker
```bash
# All platforms
docker-compose up --build
```

---

## 📋 Essential Commands

### Manual Setup
```bash
# Clone & setup
git clone <repository-url>
cd email-repo
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp env.example .env
python run.py
```

### Testing
```bash
# Health check
curl http://localhost:8000/health

# API docs
open http://localhost:8000/docs
```

### Common Operations
```bash
# Activate environment
source venv/bin/activate  # Windows: venv\Scripts\activate

# Start API
python run.py

# Run tests
python test_api.py

# Stop API
Ctrl+C
```

---

## 🔧 Troubleshooting

### Quick Fixes
```bash
# Recreate virtual environment
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Check Python version
python --version

# Check port usage
lsof -i :8000  # macOS/Linux
netstat -ano | findstr :8000  # Windows
```

### Common Issues
- **Port 8000 in use**: Change port in `.env` file
- **Permission denied**: `chmod +x setup.sh`
- **Python not found**: Install Python 3.8+ from python.org
- **Dependencies fail**: `pip install --upgrade pip setuptools wheel`

---

## 📚 Documentation

- **[Complete Setup Guide](SETUP_GUIDE.md)** - Full installation instructions
- **[API Documentation](http://localhost:8000/docs)** - Interactive API docs
- **[README](README.md)** - Project overview and features
- **[Scoring System Documentation](Domain_Security_Scoring_System_Documentation.md)** - Detailed scoring methodology

## 🎯 Quick Scoring Reference

### Industry-Standard 100-Point System
- **Core Protocols (70 pts)**: SPF (25) + DKIM (25) + DMARC (20)
- **Policy Enforcement (20 pts)**: DMARC Policy (15) + SPF Hygiene (5)
- **Advanced Features (10 pts)**: MTA-STS (4) + TLS-RPT (3) + BIMI (3)

### Risk Levels
- **90-100**: Low Risk ✅
- **70-89**: Medium Risk ⚠️
- **0-69**: High Risk ❌

### Test a Domain
```bash
curl "http://localhost:8000/api/v1/security/scan/example.com"
```

---

## 🆘 Need Help?

- Check [SETUP_GUIDE.md](SETUP_GUIDE.md) for detailed troubleshooting
- Create an issue on GitHub
- Review the troubleshooting section in the complete guide 