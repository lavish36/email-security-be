# 📚 Documentation Guide

This project has multiple documentation files, each serving a specific purpose. Here's what each file contains:

## 📖 Documentation Files

### [README.md](README.md) - **Project Overview**
- **Purpose**: Main project introduction and quick start
- **Contains**: 
  - Project description and features
  - Quick start commands (one-liners)
  - API endpoint overview
  - Basic configuration
  - Project structure
- **When to use**: First time visitors, getting project overview

### [SETUP_GUIDE.md](SETUP_GUIDE.md) - **Complete Setup Instructions**
- **Purpose**: Single source of truth for all setup instructions
- **Contains**:
  - Detailed installation for all platforms (Windows, macOS, Linux)
  - Docker setup instructions
  - Configuration guide
  - Troubleshooting section
  - Verification checklist
- **When to use**: Need detailed setup instructions, troubleshooting

### [QUICK_SETUP.md](QUICK_SETUP.md) - **Quick Reference**
- **Purpose**: Fast commands and quick fixes
- **Contains**:
  - One-command setup options
  - Essential commands
  - Quick troubleshooting
  - Common operations
- **When to use**: Need quick commands, already familiar with setup

### [DOCUMENTATION.md](DOCUMENTATION.md) - **This File**
- **Purpose**: Guide to all documentation
- **Contains**: Overview of all documentation files
- **When to use**: Understanding what documentation exists

### [Domain_Security_Scoring_System_Documentation.md](Domain_Security_Scoring_System_Documentation.md) - **Scoring System**
- **Purpose**: Detailed explanation of the industry-standard scoring system
- **Contains**: 
  - Three-category scoring framework (Core Protocols, Policy Enforcement, Advanced Features)
  - Risk level classification (Low/Medium/High Risk)
  - Scoring examples and API response structure
  - Industry alignment with tools like Easy DMARC
- **When to use**: Understanding how domains are scored, interpreting results, comparing with industry standards

## 🎯 Which File to Use?

| Scenario | Use This File |
|----------|---------------|
| **First time setup** | [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| **Quick commands** | [QUICK_SETUP.md](QUICK_SETUP.md) |
| **Project overview** | [README.md](README.md) |
| **Troubleshooting** | [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| **API reference** | http://localhost:8000/docs |
| **Understanding scoring** | [Domain_Security_Scoring_System_Documentation.md](Domain_Security_Scoring_System_Documentation.md) |

## 📋 Setup Scripts

### Automated Setup
- **Windows**: `setup.bat` or `setup.ps1`
- **macOS/Linux**: `setup.sh`
- **Docker**: `docker-compose up --build`

### Manual Setup
All manual setup instructions are in [SETUP_GUIDE.md](SETUP_GUIDE.md) to avoid duplication.

## 🔄 Documentation Updates

When updating documentation:
1. **Setup instructions**: Update only [SETUP_GUIDE.md](SETUP_GUIDE.md)
2. **Quick commands**: Update [QUICK_SETUP.md](QUICK_SETUP.md)
3. **Project features**: Update [README.md](README.md)
4. **Scoring system**: Update [Domain_Security_Scoring_System_Documentation.md](Domain_Security_Scoring_System_Documentation.md)
5. **Cross-references**: Update this file if needed

This structure ensures no duplication and clear separation of concerns. 