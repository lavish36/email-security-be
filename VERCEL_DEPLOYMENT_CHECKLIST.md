# Vercel Deployment Checklist

## ✅ Files Created/Modified for Vercel

### Required Files
1. **`vercel.json`** - Vercel configuration
   - Routes all requests to `api/index.py`
   - Sets max function duration to 60 seconds
   - Configures environment variables

2. **`api/index.py`** - Serverless function handler
   - Imports FastAPI app from `app.main`
   - Properly sets up Python path
   - Exports app for Vercel's ASGI runtime

3. **`.vercelignore`** - Excludes unnecessary files
   - Excludes venv, __pycache__, logs, etc.
   - Reduces deployment size

4. **`runtime.txt`** - Python version specification
   - Specifies Python 3.11
   - Note: Vercel may use this or auto-detect

### Modified Files
1. **`app/main.py`** - Health check fix
   - Added safety check for `start_time` initialization
   - Handles serverless cold starts

## 📋 Pre-Deployment Checklist

### 1. Environment Variables
Set these in Vercel Dashboard → Settings → Environment Variables:

**Required (Optional but recommended):**
- `IPINFO_TOKEN` - For enhanced geolocation (optional)
- `VIRUSTOTAL_API_KEY` - For virus scanning (optional)
- `SPAMHAUS_API_KEY` - For Spamhaus blacklist checks (optional)

**Optional Configuration:**
- `RATE_LIMIT_PER_MINUTE` - Default: 60
- `DNS_TIMEOUT` - Default: 20
- `DNS_RETRIES` - Default: 3
- `DNS_NAMESERVERS` - Comma-separated (e.g., "1.1.1.1,8.8.8.8")

### 2. File Structure Verification
```
email-repo/
├── api/
│   └── index.py          ✅ Vercel handler
├── app/
│   ├── __init__.py       ✅
│   ├── main.py           ✅ FastAPI app
│   ├── config.py         ✅
│   ├── api/
│   │   ├── __init__.py   ✅
│   │   └── v1/           ✅
│   ├── models/           ✅
│   ├── services/         ✅
│   └── utils/            ✅
├── requirements.txt     ✅
├── vercel.json          ✅
├── .vercelignore        ✅
└── runtime.txt          ✅
```

### 3. Dependencies Check
All dependencies in `requirements.txt` are compatible with Vercel:
- ✅ FastAPI - ASGI compatible
- ✅ uvicorn - Not needed in serverless (Vercel handles ASGI)
- ✅ pydantic - Pure Python
- ✅ dnspython - Pure Python
- ✅ cryptography - Vercel supports compiled extensions
- ✅ All other packages are standard Python packages

### 4. Import Verification
✅ All imports tested and working:
- `from app.main import app` - ✅ Works
- All module imports verified - ✅

### 5. Potential Issues & Solutions

#### Issue: Cold Start Performance
- **Solution**: Vercel keeps functions warm, but first request may be slower
- **Mitigation**: Already handled in health check endpoint

#### Issue: Function Timeout
- **Default**: 10 seconds (Hobby plan), 60 seconds (Pro plan)
- **To increase**: Set in Vercel Dashboard → Settings → Functions → Max Duration
- **Note**: Cannot set via vercel.json for auto-detected Python functions

#### Issue: Memory Limits
- **Vercel Free**: 1024 MB
- **Vercel Pro**: 3008 MB
- Should be sufficient for this application

#### Issue: DNS Resolution
- **Note**: DNS queries may be slower on serverless
- **Mitigation**: Already implemented timeout and retry logic

## 🚀 Deployment Steps

1. **Commit all files:**
   ```bash
   git add vercel.json api/index.py .vercelignore runtime.txt app/main.py
   git commit -m "Add Vercel serverless configuration"
   git push
   ```

2. **Deploy to Vercel:**
   - Connect your repository to Vercel
   - Vercel will auto-detect Python
   - Set environment variables in Vercel dashboard
   - Deploy

3. **Verify Deployment:**
   - Check `/health` endpoint
   - Check `/` root endpoint
   - Test `/docs` for Swagger UI

## 🔍 Troubleshooting

### If deployment fails:

1. **Check Vercel Build Logs:**
   - Look for import errors
   - Check for missing dependencies
   - Verify Python version

2. **Common Issues:**
   - **Import errors**: Check Python path in `api/index.py`
   - **Missing dependencies**: Verify `requirements.txt`
   - **Timeout errors**: Increase `maxDuration` in vercel.json
   - **Environment variables**: Ensure all are set in Vercel dashboard

3. **Test Locally:**
   ```bash
   # Install Vercel CLI
   npm i -g vercel
   
   # Test locally
   vercel dev
   ```

## 📝 Notes

- Vercel automatically detects FastAPI/ASGI apps
- `uvicorn` is not needed in serverless (Vercel handles ASGI)
- All routes are handled by the single `api/index.py` handler
- Environment variables from `.env` are not used - set in Vercel dashboard
- `runtime.txt` may not be used by Vercel (it auto-detects Python version)

