from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import os
from datetime import datetime

from app.config import settings
from app.api.v1 import security, generate, intelligence, guides, header_analysis
from app.models.responses import ErrorResponse


# Startup and shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.start_time = time.time()
    print(f"🚀 Domain Security API starting up...")
    yield
    # Shutdown
    print(f"🛑 Domain Security API shutting down...")


# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description="""
    # Domain Security API
    
    "Protect Your Domain. Validate Email Security. Stay Off Blacklists." 🎯
    
    A comprehensive API for domain security scanning, DNS record validation, and email security configuration.
    
    ## Features
    
    ### Security Checks
    - **SPF Validation** - Check SPF record existence, syntax, and configuration
    - **DKIM Validation** - Validate DKIM selectors and public keys
    - **DMARC Analysis** - Analyze DMARC policy and configuration
    - **BIMI Check** - Verify BIMI logo and VMC certificate
    - **TLS/STARTTLS** - Check mail server TLS configuration
    - **MX Analysis** - Analyze mail server configuration
    
    ### Record Generators
    - **SPF Generator** - Generate SPF records for email providers
    - **DKIM Generator** - Generate DKIM key pairs and DNS records
    - **DMARC Generator** - Create DMARC records with various policies
    
    ### Intelligence
    - **WHOIS Lookup** - Get domain registration information
    - **Geolocation** - Server location and ISP information
    - **Threat Intelligence** - Check domain against blacklists
    
    ### DNS Provider Guides
    - **Setup Guides** - Step-by-step instructions for popular DNS providers
    - **Provider List** - Available DNS providers and their features
    
    ## Quick Start
    
    1. **Health Check**: `GET /health`
    2. **Domain Scan**: `GET /api/v1/security/scan/{domain}`
    3. **Generate SPF**: `POST /api/v1/generate/spf`
    4. **WHOIS Lookup**: `GET /api/v1/intelligence/whois/{domain}`
    
    ## Authentication
    
    This API is currently open and doesn't require authentication. Rate limiting is applied to prevent abuse.
    
    ## Rate Limiting
    
    - **Default**: 60 requests per minute
    - **Configurable**: Via environment variables
    """,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    import traceback
    # Log the full traceback for debugging (visible in Vercel logs)
    error_traceback = traceback.format_exc()
    print(f"ERROR: Unhandled exception: {str(exc)}")
    print(f"Traceback: {error_traceback}")
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR",
            details={
                "error": str(exc),
                "type": type(exc).__name__
            }
        ).dict()
    )


# Health check endpoint
@app.get("/health", response_model=dict, tags=["Health"])
async def health_check():
    """
    Health check endpoint.
    
    Returns the current status of the API and its dependencies.
    """
    # Handle case where start_time might not be initialized (e.g., on Vercel)
    start_time = getattr(app.state, 'start_time', None)
    if start_time is None:
        app.state.start_time = time.time()
        start_time = app.state.start_time
    
    uptime = time.time() - start_time
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.api_version,
        "uptime": round(uptime, 2),
        "services": {
            "dns": "operational",
            "whois": "operational",
            "geolocation": "operational"
        }
    }


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint.
    
    Returns basic API information and links to documentation.
    """
    return {
        "message": "Domain Security API",
        "version": settings.api_version,
        "description": "Protect Your Domain. Validate Email Security. Stay Off Blacklists.",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json"
        },
        "endpoints": {
            "health": "/health",
            "security": "/api/v1/security",
            "generate": "/api/v1/generate",
            "intelligence": "/api/v1/intelligence",
            "guides": "/api/v1/guides"
        }
    }


# Include API routes
app.include_router(security.router)
app.include_router(generate.router)
app.include_router(intelligence.router)
app.include_router(guides.router)
app.include_router(header_analysis.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    ) 