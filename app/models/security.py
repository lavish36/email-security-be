from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class SecurityStatus(str, Enum):
    """Security check status."""
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    ERROR = "error"
    NOT_FOUND = "not_found"


class SPFRecord(BaseModel):
    """SPF record analysis result."""
    exists: bool = Field(..., description="Whether SPF record exists")
    record: Optional[str] = Field(None, description="Raw SPF record")
    status: SecurityStatus = Field(..., description="Overall SPF status")
    mechanisms: List[str] = Field(default=[], description="List of SPF mechanisms")
    includes: List[str] = Field(default=[], description="List of included domains")
    all_mechanism: Optional[str] = Field(None, description="The 'all' mechanism used")
    record_count: int = Field(default=0, description="Number of SPF records found")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")
    lookup_count: int = Field(default=0, description="Estimated number of DNS lookups")
    strength: str = Field(default="Unknown", description="Strength of the SPF policy (Strong, Moderate, Neutral, Weak)")
    mechanism_details: List[Dict[str, Any]] = Field(default=[], description="Detailed breakdown of mechanisms")


class DKIMRecord(BaseModel):
    """DKIM record analysis result."""
    selector: str = Field(..., description="DKIM selector used")
    exists: bool = Field(..., description="Whether DKIM record exists")
    record: Optional[str] = Field(None, description="Raw DKIM record")
    status: SecurityStatus = Field(..., description="Overall DKIM status")
    public_key: Optional[str] = Field(None, description="Public key")
    algorithm: Optional[str] = Field(None, description="Encryption algorithm")
    key_type: Optional[str] = Field(None, description="Key type (e.g., rsa)")
    key_size: Optional[int] = Field(None, description="Key size in bits")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")
    security_profile: str = Field(default="Unknown", description="Security profile based on key strength (High, Medium, Low)")


class DMARCRecord(BaseModel):
    """DMARC record analysis result."""
    exists: bool = Field(..., description="Whether DMARC record exists")
    record: Optional[str] = Field(None, description="Raw DMARC record")
    status: SecurityStatus = Field(..., description="Overall DMARC status")
    policy: Optional[str] = Field(None, description="DMARC policy")
    subdomain_policy: Optional[str] = Field(None, description="DMARC policy for subdomains")
    percentage: Optional[int] = Field(None, description="Percentage of messages filtered")
    report_uri: List[str] = Field(default=[], description="List of report URIs")
    forensic_uri: List[str] = Field(default=[], description="List of forensic URIs")
    adkim: Optional[str] = Field(None, description="DKIM alignment mode")
    aspf: Optional[str] = Field(None, description="SPF alignment mode")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")
    policy_description: Optional[str] = Field(None, description="Human-readable description of the policy")
    alignment_description: Optional[Dict[str, str]] = Field(None, description="Human-readable description of alignment settings")


class BIMIRecord(BaseModel):
    """BIMI record analysis result."""
    exists: bool = Field(..., description="Whether BIMI record exists")
    record: Optional[str] = Field(None, description="Raw BIMI record")
    status: SecurityStatus = Field(..., description="Overall BIMI status")
    logo_url: Optional[str] = Field(None, description="BIMI logo URL")
    vmc_url: Optional[str] = Field(None, description="VMC certificate URL")
    logo_accessible: bool = Field(default=False, description="Whether logo is accessible")
    vmc_valid: bool = Field(default=False, description="Whether VMC is valid")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")


class MTASTSRecord(BaseModel):
    """MTA-STS record analysis result."""
    exists: bool = Field(..., description="Whether MTA-STS record exists")
    record: Optional[str] = Field(None, description="Raw MTA-STS record")
    status: SecurityStatus = Field(..., description="Overall MTA-STS status")
    version: Optional[str] = Field(None, description="MTA-STS version")
    mode: Optional[str] = Field(None, description="MTA-STS mode (testing, enforce, none)")
    max_age: Optional[int] = Field(None, description="Policy max age in seconds")
    mx_records: List[str] = Field(default=[], description="List of MX records in policy")
    policy_accessible: bool = Field(default=False, description="Whether policy file is accessible")
    policy_valid: bool = Field(default=False, description="Whether policy file is valid")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")


class TLSRPTRecord(BaseModel):
    """TLS-RPT record analysis result."""
    exists: bool = Field(..., description="Whether TLS-RPT record exists")
    record: Optional[str] = Field(None, description="Raw TLS-RPT record")
    status: SecurityStatus = Field(..., description="Overall TLS-RPT status")
    version: Optional[str] = Field(None, description="TLS-RPT version")
    rua: List[str] = Field(default=[], description="List of report URIs")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")


class TLSRecord(BaseModel):
    """TLS/STARTTLS analysis result."""
    mx_records: List[str] = Field(default=[], description="List of MX records")
    starttls_support: Dict[str, bool] = Field(default={}, description="STARTTLS support per server")
    tls_version: Dict[str, str] = Field(default={}, description="TLS version per server")
    certificate_valid: Dict[str, bool] = Field(default={}, description="Certificate validity per server")
    status: SecurityStatus = Field(..., description="Overall TLS status")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")


class DNSSECRecord(BaseModel):
    """DNSSEC analysis result."""
    enabled: bool = Field(..., description="Whether DNSSEC is enabled")
    status: SecurityStatus = Field(..., description="Overall DNSSEC status")
    dnskey_records: int = Field(default=0, description="Number of DNSKEY records")
    ds_records: int = Field(default=0, description="Number of DS records")
    rrsig_records: int = Field(default=0, description="Number of RRSIG records")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")
    details: Dict[str, Any] = Field(default={}, description="Detailed DNSSEC information")


class MXRecord(BaseModel):
    """MX record analysis result."""
    records: List[Dict[str, Any]] = Field(default=[], description="List of MX records")
    status: SecurityStatus = Field(..., description="Overall MX status")
    primary_mx: Optional[str] = Field(None, description="Primary MX server")
    backup_mx_count: int = Field(default=0, description="Number of backup MX servers")
    security_score: int = Field(default=0, description="MX security score (0-10)")
    open_relay_risk: bool = Field(default=False, description="Whether open relay risk is detected")
    warnings: List[str] = Field(default=[], description="List of warnings")
    recommendations: List[str] = Field(default=[], description="List of recommendations")


class SecurityScanResult(BaseModel):
    """Comprehensive security scan result."""
    domain: str = Field(..., description="Domain name")
    scan_timestamp: str = Field(..., description="Scan timestamp")
    overall_status: SecurityStatus = Field(..., description="Overall security status")
    spf: SPFRecord = Field(..., description="SPF analysis")
    dkim: List[DKIMRecord] = Field(default=[], description="DKIM analysis for all selectors")
    dmarc: DMARCRecord = Field(..., description="DMARC analysis")
    bimi: BIMIRecord = Field(..., description="BIMI analysis")
    mtasts: MTASTSRecord = Field(..., description="MTA-STS analysis")
    tlsrpt: TLSRPTRecord = Field(..., description="TLS-RPT analysis")
    tls: TLSRecord = Field(..., description="TLS analysis")
    mx: MXRecord = Field(..., description="MX analysis")
    score: int = Field(..., description="Security score (0-100)")
    overall_score: int = Field(..., description="Overall security score (0-100)")
    summary: List[str] = Field(default=[], description="Summary of findings")
    quick_summary: Optional[str] = Field(default=None, description="Quick overview summary for immediate assessment")
    summary_text: Optional[str] = Field(default=None, description="Human-readable summary text with risk assessment")
    ai_summary: Optional[str] = Field(default=None, description="AI-generated comprehensive summary of security scan results")
    recommendations: List[str] = Field(default=[], description="Overall recommendations")
    scoring_breakdown: Optional[Dict[str, Any]] = Field(default=None, description="Detailed scoring breakdown by category")
    risk_assessment: Optional[Dict[str, Any]] = Field(default=None, description="Comprehensive risk assessment with detailed description")
    industry_standard_assessment: Optional[Dict[str, Any]] = Field(default=None, description="Industry standard 10-point scale risk assessment")
    protocol_status: Optional[Dict[str, Any]] = Field(default=None, description="Detailed status summary for all security protocols")


class GeneratedRecord(BaseModel):
    """Generated DNS record result with enhanced metadata."""
    record_type: str = Field(..., description="Type of DNS record")
    name: str = Field(..., description="Record name")
    value: str = Field(..., description="Record value")
    ttl: int = Field(default=3600, description="TTL value")
    instructions: List[str] = Field(default=[], description="Setup instructions")
    warnings: List[str] = Field(default=[], description="List of warnings")
    
    # New enhanced fields
    validation: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Validation metadata including syntax check, DNS lookup count, etc."
    )
    export_formats: Optional[Dict[str, str]] = Field(
        default=None,
        description="Record in different export formats (BIND, JSON, etc.)"
    )
    related_records: Optional[List[Dict[str, str]]] = Field(
        default=None,
        description="Related DNS records user should consider creating"
    )
    provider_guides: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="DNS provider-specific setup guides"
    )
    estimated_propagation_time: Optional[str] = Field(
        default="1-24 hours",
        description="Estimated DNS propagation time"
    )