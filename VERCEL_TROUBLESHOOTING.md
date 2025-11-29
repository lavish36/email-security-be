# Vercel Deployment Troubleshooting Guide

## Issue: 500 Internal Server Error on Root Endpoint

### Changes Made to Fix the Issue

1. **Enhanced Error Logging in `api/index.py`**
   - Added detailed error logging with traceback
   - Shows Python path and project root for debugging
   - Helps identify import errors quickly

2. **Robust GPT Summarizer Initialization**
   - Made `gpt_summarizer` initialization fault-tolerant
   - Falls back to dummy instance if initialization fails
   - Prevents module import errors from crashing the app

3. **Improved Global Exception Handler**
   - Added full traceback logging in `app/main.py`
   - Errors are logged to Vercel console for debugging
   - Better error details in response

4. **Updated `vercel.json`**
   - Added function configuration with 60s timeout
   - Added build command for dependencies

### How to Debug

1. **Check Vercel Function Logs**
   - Go to Vercel Dashboard → Your Project → Functions
   - Click on the failed function
   - Check "Logs" tab for detailed error messages
   - Look for the traceback and error details

2. **Common Issues and Solutions**

   **Issue: Import Errors**
   ```
   ERROR: Failed to import app: ...
   ```
   - **Solution**: Check that all dependencies are in `requirements.txt`
   - Verify Python path is correct in `api/index.py`
   - Ensure all `__init__.py` files exist

   **Issue: Missing Environment Variables**
   ```
   ValidationError: ...
   ```
   - **Solution**: Set all required environment variables in Vercel Dashboard
   - Go to Settings → Environment Variables
   - Add: `OPENROUTER_API_KEY` (optional but recommended)

   **Issue: Module Initialization Errors**
   ```
   ERROR: GPT summarizer initialization failed
   ```
   - **Solution**: This is now handled gracefully - app will work without AI summary
   - Check that `OPENROUTER_API_KEY` is set correctly if you want AI summaries

   **Issue: Timeout Errors**
   ```
   Function execution exceeded timeout
   ```
   - **Solution**: Already set to 60s in `vercel.json`
   - For Pro plan, can increase in Vercel Dashboard → Settings → Functions

3. **Test Locally with Vercel CLI**
   ```bash
   # Install Vercel CLI
   npm i -g vercel
   
   # Test locally
   vercel dev
   ```
   This will simulate the Vercel environment locally and help identify issues.

4. **Check Build Logs**
   - Go to Vercel Dashboard → Deployments
   - Click on the failed deployment
   - Check "Build Logs" for dependency installation issues

### Environment Variables Checklist

Make sure these are set in Vercel Dashboard → Settings → Environment Variables:

**Optional (but recommended):**
- `OPENROUTER_API_KEY` - For AI summaries (optional)
- `OPENROUTER_SITE_URL` - Optional, for OpenRouter rankings
- `OPENROUTER_SITE_NAME` - Optional, for OpenRouter rankings

**Other optional variables:**
- `IPINFO_TOKEN` - For enhanced geolocation
- `VIRUSTOTAL_API_KEY` - For virus scanning
- `SPAMHAUS_API_KEY` - For Spamhaus checks

**Note**: The app will work without any of these - they're all optional.

### Quick Fix Steps

1. **Redeploy after changes:**
   ```bash
   git add .
   git commit -m "Fix Vercel deployment issues"
   git push
   ```

2. **Check Vercel Logs:**
   - Wait for deployment to complete
   - Check function logs for specific error
   - Look for the detailed traceback we added

3. **Test the endpoint:**
   - Try `/health` endpoint first (simplest)
   - Then try `/` root endpoint
   - Check `/docs` for Swagger UI

### If Still Failing

1. **Check the specific error in logs:**
   - The enhanced error logging will show exactly what's failing
   - Look for "ERROR: Failed to import app" or similar

2. **Verify file structure:**
   ```
   email-repo/
   ├── api/
   │   └── index.py          ✅ Must exist
   ├── app/
   │   ├── __init__.py       ✅ Must exist
   │   ├── main.py           ✅ Must exist
   │   └── ...
   ├── requirements.txt      ✅ Must exist
   └── vercel.json           ✅ Must exist
   ```

3. **Test imports locally:**
   ```bash
   python -c "from app.main import app; print('Import successful')"
   ```

4. **Check Python version:**
   - Vercel auto-detects Python version
   - Ensure `requirements.txt` has compatible packages
   - Check `runtime.txt` if you have one

### Additional Notes

- The app is now more fault-tolerant - it will work even if some optional features fail to initialize
- GPT summarizer will gracefully degrade if OpenRouter API key is not set
- All errors are logged to Vercel console for debugging
- The root endpoint should now work even if some modules have issues

