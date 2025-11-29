from typing import Optional, Any, Dict, List, Generic, TypeVar
from pydantic import BaseModel, Field
from datetime import datetime

T = TypeVar('T')


class BaseResponse(BaseModel):
    """Base API response model."""
    success: bool = Field(..., description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")


class SuccessResponse(BaseResponse, Generic[T]):
    """Success response model."""
    success: bool = Field(default=True, description="Request was successful")
    data: T = Field(..., description="Response data")


class ErrorResponse(BaseResponse):
    """Error response model."""
    success: bool = Field(default=False, description="Request failed")
    error_code: str = Field(..., description="Error code")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")


class HealthCheckResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    version: str = Field(..., description="API version")
    uptime: float = Field(..., description="Service uptime in seconds")
    services: Dict[str, str] = Field(default={}, description="Status of dependent services")


class DNSProviderInfo(BaseModel):
    """DNS provider information model."""
    name: str = Field(..., description="Provider name")
    slug: str = Field(..., description="Provider slug")
    website: str = Field(..., description="Provider website")
    supported_records: List[str] = Field(default=[], description="Supported record types")
    description: str = Field(..., description="Provider description")


class DNSProviderGuide(BaseModel):
    """DNS provider setup guide model."""
    provider: str = Field(..., description="Provider name")
    steps: List[Dict[str, Any]] = Field(default=[], description="Setup steps")
    screenshots: List[str] = Field(default=[], description="Screenshot URLs")
    tips: List[str] = Field(default=[], description="Setup tips")
    common_issues: List[str] = Field(default=[], description="Common issues and solutions")


class WHOISInfo(BaseModel):
    """WHOIS information model."""
    domain: str = Field(..., description="Domain name")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    creation_date: Optional[datetime] = Field(None, description="Domain creation date")
    expiration_date: Optional[datetime] = Field(None, description="Domain expiration date")
    updated_date: Optional[datetime] = Field(None, description="Last update date")
    status: List[str] = Field(default=[], description="Domain status")
    name_servers: List[str] = Field(default=[], description="Name servers")
    dnssec: Optional[str] = Field(None, description="DNSSEC status")


class GeolocationInfo(BaseModel):
    """Geolocation information model."""
    ip: str = Field(..., description="IP address")
    country: Optional[str] = Field(None, description="Country")
    region: Optional[str] = Field(None, description="Region/State")
    city: Optional[str] = Field(None, description="City")
    latitude: Optional[float] = Field(None, description="Latitude")
    longitude: Optional[float] = Field(None, description="Longitude")
    timezone: Optional[str] = Field(None, description="Timezone")
    isp: Optional[str] = Field(None, description="Internet Service Provider")
    org: Optional[str] = Field(None, description="Organization")


class BlacklistResult(BaseModel):
    """Individual blacklist check result."""
    blacklist: str = Field(..., description="Blacklist identifier")
    name: str = Field(..., description="Blacklist name")
    description: str = Field(..., description="Blacklist description")
    listed: bool = Field(..., description="Whether domain is listed")
    response: Optional[str] = Field(None, description="Blacklist response")
    severity: str = Field(..., description="Severity level")
    category: str = Field(..., description="Blacklist category")
    lookup_domain: Optional[str] = Field(None, description="DNS lookup domain")
    error: Optional[str] = Field(None, description="Error message if any")


class ThreatIntelligence(BaseModel):
    """Threat intelligence information model."""
    domain: str = Field(..., description="Domain name")
    ip_address: Optional[str] = Field(None, description="Resolved IP address")
    blacklisted: bool = Field(..., description="Whether domain is blacklisted")
    blacklist_count: int = Field(..., description="Number of blacklists domain is listed on")
    reputation_score: int = Field(..., description="Reputation score (0-100)")
    risk_level: str = Field(..., description="Risk level (low, medium, high, critical)")
    blacklists: List[BlacklistResult] = Field(default=[], description="Detailed blacklist results")
    summary: str = Field(..., description="Human-readable summary")
    timestamp: str = Field(..., description="Check timestamp")
    last_seen: Optional[datetime] = Field(None, description="Last seen in malicious activity")
    categories: List[str] = Field(default=[], description="Threat categories")
    details: Dict[str, Any] = Field(default={}, description="Additional threat details") 