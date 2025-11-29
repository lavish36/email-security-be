from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator
import re


class DomainRequest(BaseModel):
    """Base domain request model."""
    domain: str = Field(..., description="Domain name to analyze", example="example.com")
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain format."""
        if not v:
            raise ValueError("Domain cannot be empty")
        
        # Remove protocol if present
        v = v.lower().replace('http://', '').replace('https://', '').replace('www.', '')
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, v):
            raise ValueError("Invalid domain format")
        
        return v


class SPFGeneratorRequest(BaseModel):
    """SPF record generator request."""
    domain: str = Field(..., description="Domain name", example="example.com")
    email_providers: List[str] = Field(
        default=[],
        description="List of email providers to include",
        example=["google", "outlook", "sendgrid", "mailgun"]
    )
    include_all: bool = Field(
        default=False,
        description="Include all common email providers"
    )
    custom_mechanisms: List[str] = Field(
        default=[],
        description="Custom SPF mechanisms to include",
        example=["ip4:192.168.1.1", "include:_spf.example.com"]
    )


class DKIMGeneratorRequest(BaseModel):
    """DKIM key generator request."""
    domain: str = Field(..., description="Domain name", example="example.com")
    selector: str = Field(
        default="default",
        description="DKIM selector name",
        example="default"
    )
    key_size: int = Field(
        default=2048,
        description="RSA key size in bits",
        ge=1024,
        le=4096
    )
    algorithm: str = Field(
        default="rsa-sha256",
        description="DKIM signing algorithm",
        example="rsa-sha256"
    )


class DMARCGeneratorRequest(BaseModel):
    """DMARC record generator request."""
    domain: str = Field(..., description="Domain name", example="example.com")
    policy: str = Field(
        default="none",
        description="DMARC policy",
        example="none"
    )
    subdomain_policy: str = Field(
        default="none",
        description="DMARC policy for subdomains",
        example="none"
    )
    percentage: int = Field(
        default=100,
        description="Percentage of messages subject to filtering",
        ge=0,
        le=100
    )
    report_uri: Optional[str] = Field(
        default=None,
        description="URI for aggregate reports",
        example="mailto:dmarc@example.com"
    )
    forensic_uri: Optional[str] = Field(
        default=None,
        description="URI for forensic reports",
        example="mailto:dmarc-forensic@example.com"
    )
    adkim: str = Field(
        default="r",
        description="DKIM alignment mode",
        example="r"
    )
    aspf: str = Field(
        default="r",
        description="SPF alignment mode",
        example="r"
    )


class MTASTSGeneratorRequest(BaseModel):
    """MTA-STS record generator request."""
    domain: str = Field(..., description="Domain name", example="example.com")
    mode: str = Field(
        default="testing",
        description="MTA-STS mode",
        example="testing"
    )
    max_age: int = Field(
        default=86400,
        description="Policy max age in seconds",
        ge=300,
        le=31536000
    )
    mx_records: List[str] = Field(
        default=[],
        description="List of MX records to include in policy",
        example=["mail1.example.com", "mail2.example.com"]
    )
    include_subdomains: bool = Field(
        default=False,
        description="Include subdomains in policy"
    )


class TLSRPTGeneratorRequest(BaseModel):
    """TLS-RPT record generator request."""
    domain: str = Field(..., description="Domain name", example="example.com")
    report_uri: str = Field(
        default="mailto:tls-reports@example.com",
        description="URI for TLS reports",
        example="mailto:tls-reports@example.com"
    )
    include_subdomains: bool = Field(
        default=False,
        description="Include subdomains in reporting"
    )


class SecurityScanRequest(BaseModel):
    """Comprehensive security scan request."""
    domain: str = Field(..., description="Domain name to scan", example="example.com")
    include_whois: bool = Field(
        default=True,
        description="Include WHOIS information"
    )
    include_geolocation: bool = Field(
        default=True,
        description="Include server geolocation"
    )
    include_threat_intel: bool = Field(
        default=True,
        description="Include threat intelligence"
    )
    dkim_selectors: List[str] = Field(
        default=["default", "google", "selector1", "selector2", "k1", "mandrill", "s1", "s2"],
        description="DKIM selectors to check"
    ) 