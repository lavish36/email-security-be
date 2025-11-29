"""
Vercel serverless function handler for FastAPI application.
"""
import sys
import os
import traceback

# Add the project root to Python path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    # Import the FastAPI app
    # Vercel's @vercel/python runtime automatically detects FastAPI/ASGI apps
    from app.main import app
except Exception as e:
    # Print detailed error for debugging in Vercel logs
    print(f"ERROR: Failed to import app: {str(e)}")
    print(f"Traceback: {traceback.format_exc()}")
    print(f"Python path: {sys.path}")
    print(f"Project root: {project_root}")
    print(f"Current directory: {os.getcwd()}")
    raise

