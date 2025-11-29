#!/usr/bin/env python3
"""
Domain Security API - Startup Script

This script starts the FastAPI application with proper configuration.
"""

import uvicorn
from app.config import settings

if __name__ == "__main__":
    print("🚀 Starting Domain Security API...")
    print(f"📖 API Documentation: http://{settings.host}:{settings.port}/docs")
    print(f"📋 ReDoc Documentation: http://{settings.host}:{settings.port}/redoc")
    print(f"🔍 Health Check: http://{settings.host}:{settings.port}/health")
    print("=" * 60)
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info" if settings.debug else "warning"
    ) 