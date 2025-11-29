# Domain Security Backend API

"Protect Your Domain. Validate Email Security. Stay Off Blacklists." 🎯

A powerful Python FastAPI backend that provides comprehensive domain security scanning, DNS record validation, and email security configuration tools with production-grade edge case handling.

## Features

### Core Security Checks (Enhanced)
- ✅ **SPF Check** - Deep analysis with:
  - Syntax validation and mechanism breakdown
  - DNS lookup counting (RFC 7208 compliance)
  - Strength assessment (Strong/Moderate/Weak/Neutral)
  - Human-readable mechanism descriptions
- ✅ **DKIM Check** - Advanced validation with:
  - Multi-selector discovery
  - Key strength analysis (2048/1024/512-bit)
  - Security profile assessment (High/Medium/Low)
  - Algorithm and key type detection
- ✅ **DMARC Check** - Comprehensive analysis with:
  - Policy explanation (reject/quarantine/none)
  - Alignment mode descriptions (strict/relaxed)
  - Reporting URI validation
  - Percentage and subdomain policy checks
- 🕵️ **BIMI Check** - Checks for the presence and validity of BIMI logos and VMC certificates
- 🌍 **Mail Server TLS Check** - Detects STARTTLS support for domain MX records
- 📫 **MX Record Analysis** - Displays mail servers and compares against industry best practices
- 🔒 **MTA-STS Check** - Validates MTA-STS policy configuration
- 📊 **TLS-RPT Check** - Checks TLS-RPT reporting configuration
- 🛡️ **DNSSEC Check** - Validates DNSSEC implementation

### New Diagnostic Tools
- 🔄 **Reverse DNS (PTR) Lookup** - Validates reverse DNS with:
  - Forward-Confirmed reverse DNS (FCrDNS) validation
  - IPv4 and IPv6 support
  - Email deliverability insights
- 🔍 **Port Scanner** - Scans common mail server ports:
  - SMTP (25, 587, 465)
  - IMAP (143, 993)
  - POP3 (110, 995)
  - Security recommendations based on open ports
- 🚫 **Multi-RBL Blacklist Check** - Comprehensive blacklist checking:
  - 8+ major RBL providers (Spamhaus, SpamCop, Barracuda, SORBS, etc.)
  - Detailed status per RBL
  - Severity classification
  - Delisting recommendations

### Industry-Standard Scoring System
Our scoring matrix aligns with industry standards like Easy DMARC and provides a comprehensive 100-point evaluation:

**Core Protocols (70 points)**
- SPF: 25 points (pass=25, warning=15, fail=5)
- DKIM: 25 points (pass=25, warning=15, error=10, fail=5)  
- DMARC: 20 points (pass=20, warning=10, fail=5)

**Policy Enforcement (20 points)**
- DMARC Policy: 15 points (reject=15, quarantine=10, none=5)
- SPF Hygiene: 5 points (proper mechanisms)

**Advanced Features (10 points)**
- MTA-STS: 4 points
- TLS-RPT: 3 points
- BIMI: 3 points

**Risk Levels:**
- 90-100: Low Risk (Excellent security posture)
- 70-89: Medium Risk (Good security with room for improvement)
- 0-69: High Risk (Critical security issues)

### Tools & Generators
- 🛠️ **SPF Generator** - Generates SPF records based on selected email providers
- 🔐 **DKIM Key Generator** - Generates DKIM key pairs and provides DNS TXT setup instructions
- 🛠️ **DMARC Generator** - Assists in creating DMARC records with various enforcement options
- 🔒 **MTA-STS Generator** - Creates MTA-STS policy files and DNS records
- 📊 **TLS-RPT Generator** - Generates TLS-RPT reporting configuration

### Intelligence & Analysis
- 📍 **Geolocation of Servers** - Maps the IP location of email infrastructure
- ⚠️ **Threat Intelligence** - Checks the domain against known blacklists
- 📅 **WHOIS Lookup** - Displays registrar information, domain age, expiry date, and DNSSEC presence
- 📘 **DNS Provider Guide** - Provides step-by-step setup documentation for popular DNS providers
- 🔍 **DNS Record Analysis** - Comprehensive DNS record inspection

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Git (optional, for cloning)

### One-Command Setup

**Windows:**
```cmd
setup.bat
```

**macOS/Linux:**
```bash
chmod +x setup.sh && ./setup.sh
```

**Docker:**
```bash
docker-compose up --build
```

### Manual Setup (5 Steps)
```bash
# 1. Clone repository
git clone <repository-url>
cd email-repo

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp env.example .env

# 5. Start the API
python run.py
```

### 📚 Setup Documentation
- **[Complete Setup Guide](SETUP_GUIDE.md)** - Detailed instructions for all platforms
- **[Quick Setup Reference](QUICK_SETUP.md)** - Commands and troubleshooting
- **[Documentation Guide](DOCUMENTATION.md)** - Overview of all documentation files

### API Documentation
Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints

### Health & Status
- `GET /health` - API health check and status information
- `GET /` - Root endpoint with API information and documentation links

### Domain Security Checks
- `GET /api/v1/security/scan/{domain}` - Comprehensive domain security scan with scoring
- `GET /api/v1/security/spf/{domain}` - SPF record validation and analysis with strength assessment
- `GET /api/v1/security/dkim/{domain}` - DKIM record validation with security profiling (checks 8 common selectors)
- `GET /api/v1/security/dmarc/{domain}` - DMARC record validation with policy explanations
- `GET /api/v1/security/bimi/{domain}` - BIMI record validation and logo verification
- `GET /api/v1/security/tls/{domain}` - TLS/STARTTLS validation for mail servers
- `GET /api/v1/security/mx/{domain}` - MX record analysis and mail server configuration
- `GET /api/v1/security/mtasts/{domain}` - MTA-STS policy validation
- `GET /api/v1/security/tlsrpt/{domain}` - TLS-RPT reporting configuration check
- `GET /api/v1/security/dnssec/{domain}` - DNSSEC implementation validation

### New Diagnostic Tools
- `GET /api/v1/security/reverse-dns/{ip_address}` - Reverse DNS (PTR) lookup with FCrDNS validation
- `GET /api/v1/security/port-scan/{hostname}` - Scan common mail server ports (SMTP, IMAP, POP3)
- `GET /api/v1/security/blacklist-check/{ip_address}` - Check IP against 8+ major RBL providers

### Record Generators
- `POST /api/v1/generate/spf` - Generate SPF records for email providers
- `POST /api/v1/generate/dkim` - Generate DKIM key pairs and DNS records
- `POST /api/v1/generate/dmarc` - Generate DMARC records with various policies
- `POST /api/v1/generate/mtasts` - Generate MTA-STS policy files and DNS records
- `POST /api/v1/generate/tlsrpt` - Generate TLS-RPT reporting configuration
- `GET /api/v1/generate/spf/providers` - Get list of available email providers for SPF generation
- `GET /api/v1/generate/dmarc/policies` - Get available DMARC policy options

### Intelligence & Lookups
- `GET /api/v1/intelligence/whois/{domain}` - WHOIS information and domain details
- `GET /api/v1/intelligence/geolocation/{domain}` - Server geolocation and ISP information
- `GET /api/v1/intelligence/threat/{domain}` - Threat intelligence and blacklist checking
- `GET /api/v1/intelligence/threat/{domain}/detailed` - Detailed threat analysis
- `GET /api/v1/intelligence/blacklists/info` - Information about supported blacklists
- `GET /api/v1/intelligence/dns/{domain}` - Comprehensive DNS record analysis

### DNS Provider Guides
- `GET /api/v1/guides/providers` - List available DNS providers and their features
- `GET /api/v1/guides/{provider}` - Get setup guide for specific DNS provider
- `GET /api/v1/guides/{provider}/spf` - SPF setup guide for specific DNS provider
- `GET /api/v1/guides/{provider}/dmarc` - DMARC setup guide for specific DNS provider

## Configuration

### Environment Variables
Create a `.env` file with:

```env
# API Configuration
API_TITLE=Domain Security API
API_VERSION=1.0.0
DEBUG=True

# External API Keys (Optional)
IPINFO_TOKEN=your_ipinfo_token
VIRUSTOTAL_API_KEY=your_virustotal_key
SPAMHAUS_API_KEY=your_spamhaus_key

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
```

### Optional API Keys
For enhanced features, obtain API keys from:
- **IPInfo**: [ipinfo.io](https://ipinfo.io/) - Geolocation data
- **VirusTotal**: [virustotal.com](https://virustotal.com/) - Threat intelligence
- **Spamhaus**: [spamhaus.org](https://spamhaus.org/) - Blacklist checking

## Project Structure

```
app/
├── main.py                 # FastAPI application entry point
├── config.py              # Configuration settings
├── models/                # Pydantic models
│   ├── __init__.py
│   ├── domain.py          # Domain-related models
│   ├── security.py        # Security check models
│   └── responses.py       # API response models
├── services/              # Business logic
│   ├── __init__.py
│   ├── dns_service.py     # DNS resolution and validation
│   ├── security_service.py # Security checks (SPF, DKIM, DMARC)
│   ├── intelligence_service.py # WHOIS, geolocation, threat intel
│   └── generator_service.py # Record generators
├── api/                   # API routes
│   ├── __init__.py
│   ├── v1/
│   │   ├── __init__.py
│   │   ├── security.py    # Security check endpoints
│   │   ├── generate.py    # Record generator endpoints
│   │   ├── intelligence.py # Intelligence endpoints
│   │   └── guides.py      # DNS provider guides
└── utils/                 # Utility functions
    ├── __init__.py
    ├── dns_utils.py       # DNS helper functions
    ├── crypto_utils.py    # Cryptographic utilities
    └── validation_utils.py # Input validation
```
