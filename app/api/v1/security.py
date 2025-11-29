from fastapi import APIRouter, HTTPException, Query, Path
from typing import List, Optional
import asyncio
from datetime import datetime

from app.models.domain import SecurityScanRequest
from app.models.security import (
    SPFRecord, DKIMRecord, DMARCRecord, BIMIRecord, TLSRecord, MXRecord,
    SecurityScanResult, MTASTSRecord, TLSRPTRecord, DNSSECRecord, SecurityStatus
)
from app.models.responses import SuccessResponse, ErrorResponse
from app.services.dns_service import dns_service
from app.utils.validation_utils import DomainValidator
from app.utils.gpt_summarizer import gpt_summarizer

def _generate_risk_assessment(overall_status, spf_result: dict, dkim_results: list, dmarc_result: dict, final_score: int) -> dict:
    """Generate comprehensive risk assessment description."""
    
    # Map SecurityStatus to risk levels
    if overall_status == SecurityStatus.FAIL:  # high_risk
        description = "A domain with a high security risk level indicates critical vulnerabilities in SPF, DKIM, and DMARC, posing a severe threat of email impersonation and phishing attacks, necessitating urgent protocol enhancements."
        severity = "Critical"
        action_required = "Immediate action required"
    elif overall_status == SecurityStatus.WARNING:  # medium_risk
        description = "A domain with a medium security risk level shows partial implementation of email security protocols, leaving it vulnerable to targeted attacks and requiring strategic improvements."
        severity = "Moderate"
        action_required = "Action recommended"
    else:  # SecurityStatus.PASS (low_risk)
        description = "A domain with a low security risk level demonstrates strong implementation of email security protocols, providing robust protection against email-based attacks."
        severity = "Low"
        action_required = "Maintain current security posture"
    
    # Identify specific vulnerabilities
    vulnerabilities = []
    if not spf_result.get('exists', False):
        vulnerabilities.append("SPF record missing")
    if not any(dkim.get('exists', False) for dkim in (dkim_results or []) if dkim is not None):
        vulnerabilities.append("DKIM records missing")
    if not dmarc_result.get('exists', False):
        vulnerabilities.append("DMARC record missing")
    
    return {
        "level": overall_status,
        "severity": severity,
        "description": description,
        "action_required": action_required,
        "score": final_score,
        "critical_vulnerabilities": vulnerabilities
    }

def _generate_industry_standard_risk_assessment(industry_score: int, industry_risk: str, spf_result: dict, dkim_results: list, dmarc_result: dict) -> dict:
    """Generate industry standard 10-point scale risk assessment description."""
    
    if industry_risk == 'high_risk':
        description = "A high security risk level indicates critical vulnerabilities in SPF, DKIM, and DMARC, posing a severe threat of email impersonation and phishing attacks, necessitating urgent protocol enhancements."
        severity = "Critical"
        action_required = "Immediate action required"
    elif industry_risk == 'medium_risk':
        description = "A medium security risk level signals notable SPF, DKIM, and DMARC issues, posing a potential risk of email spoofing; prompt resolution is recommended to strengthen overall security."
        severity = "Moderate"
        action_required = "Action recommended"
    else:  # low_risk
        description = "A low security risk level demonstrates strong implementation of email security protocols, providing robust protection against email-based attacks."
        severity = "Low"
        action_required = "Maintain current security posture"
    
    # Identify specific vulnerabilities
    vulnerabilities = []
    if not spf_result.get('exists', False):
        vulnerabilities.append("SPF record missing")
    if not any(dkim.get('exists', False) for dkim in (dkim_results or []) if dkim is not None):
        vulnerabilities.append("DKIM records missing")
    if not dmarc_result.get('exists', False):
        vulnerabilities.append("DMARC record missing")
    elif dmarc_result.get('subdomain_policy') == 'none':
        vulnerabilities.append("DMARC subdomain policy set to none")
    
    return {
        "level": industry_risk,
        "severity": severity,
        "description": description,
        "action_required": action_required,
        "score": industry_score,
        "critical_vulnerabilities": vulnerabilities
    }

def _get_industry_standard_status(protocol: str, result: dict, dkim_results: list = None) -> str:
    """Get industry standard status (Valid, Warning, Risky) for a protocol."""
    
    if protocol == "spf":
        if not result.get('exists', False):
            return "Risky"
        elif result.get('status') == 'pass':
            return "Valid"
        elif result.get('status') == 'warning':
            return "Warning"
        else:
            return "Risky"
    
    elif protocol == "dkim":
        if not dkim_results or not any(dkim.get('exists', False) for dkim in dkim_results if dkim is not None):
            return "Risky"
        elif any(dkim.get('status') == 'pass' for dkim in dkim_results if dkim is not None):
            return "Valid"
        elif any(dkim.get('status') == 'warning' for dkim in dkim_results if dkim is not None):
            return "Warning"
        elif any(dkim.get('status') == 'error' for dkim in dkim_results if dkim is not None):
            # If all DKIM records have errors (timeouts), treat as missing
            if all(dkim.get('status') == 'error' for dkim in dkim_results if dkim is not None):
                return "Risky"
            else:
                return "Warning"
        else:
            return "Risky"
    
    elif protocol == "dmarc":
        if not result.get('exists', False):
            return "Risky"
        elif result.get('status') == 'pass':
            # Check main policy - if it's 'none', it's a warning
            main_policy = result.get('policy', 'none')
            if main_policy == 'none':
                return "Warning"
            # Check subdomain policy - if it's 'none', it's a warning
            elif result.get('subdomain_policy') == 'none':
                return "Warning"
            else:
                return "Valid"
        elif result.get('status') == 'warning':
            return "Warning"
        else:
            return "Risky"
    
    return "Unknown"

def _generate_summary_text(overall_status, spf_result: dict, dkim_results: list, dmarc_result: dict, final_score: int, industry_score: int) -> str:
    """Generate dynamic summary text based on actual findings."""
    
    # Get status indicators
    spf_status = _get_industry_standard_status("spf", spf_result)
    dkim_status = _get_industry_standard_status("dkim", {}, dkim_results)
    dmarc_status = _get_industry_standard_status("dmarc", dmarc_result)
    
    # Count issues
    risky_count = sum(1 for status in [spf_status, dkim_status, dmarc_status] if status == "Risky")
    warning_count = sum(1 for status in [spf_status, dkim_status, dmarc_status] if status == "Warning")
    valid_count = sum(1 for status in [spf_status, dkim_status, dmarc_status] if status == "Valid")
    
    # Generate concise summary based on overall_status (primary) and findings (secondary)
    if overall_status == SecurityStatus.FAIL:  # high_risk
        summary = f"Risk Assessment Level: High\n\n"
        if risky_count >= 2:
            summary += "A domain with a high security risk level indicates critical vulnerabilities in SPF, DKIM, and DMARC, posing a severe threat of email impersonation and phishing attacks, necessitating urgent protocol enhancements."
        else:
            summary += "A domain with a high security risk level indicates significant vulnerabilities in email security protocols, posing a substantial threat of email spoofing and phishing attacks. Immediate action is required to implement missing security measures."
    
    elif overall_status == SecurityStatus.WARNING:  # medium_risk
        summary = f"Risk Assessment Level: Medium\n\n"
        if warning_count >= 2:
            summary += "A medium security risk level signals notable SPF, DKIM, and DMARC issues, posing a potential risk of email spoofing; prompt resolution is recommended to strengthen overall security."
        else:
            summary += "A medium security risk level indicates some vulnerabilities in email security protocols that should be addressed to improve protection against email-based attacks."
    
    else:  # SecurityStatus.PASS (low_risk)
        summary = f"Risk Assessment Level: Low\n\n"
        if valid_count >= 2:
            summary += "A domain with a low security risk level demonstrates strong implementation of email security protocols, providing robust protection against email-based attacks."
        else:
            summary += "A domain with a low security risk level demonstrates adequate implementation of email security protocols, providing reasonable protection against email-based attacks."
    
    # Add brief key findings
    summary += "\n\nKey Findings:\n"
    
    if spf_status == "Risky":
        summary += "• SPF record is missing or misconfigured\n"
    elif spf_status == "Warning":
        summary += "• SPF record has configuration issues\n"
    else:
        summary += "• SPF record is properly configured\n"
    
    if dkim_status == "Risky":
        summary += "• DKIM records are missing\n"
    elif dkim_status == "Warning":
        summary += "• DKIM records have configuration issues\n"
    else:
        summary += "• DKIM records are properly configured\n"
    
    if dmarc_status == "Risky":
        summary += "• DMARC record is missing\n"
    elif dmarc_status == "Warning":
        summary += "• DMARC record has issues (e.g., subdomain policy set to 'none')\n"
    else:
        summary += "• DMARC record is properly configured\n"
    
    # Add score information
    summary += f"\nOverall Score: {final_score}/100 (Comprehensive) | {industry_score}/10 (Industry Standard)"
    
    # Add note about detailed information
    summary += "\n\n📋 Detailed analysis and recommendations are available in the full response below."
    
    return summary

def _generate_quick_summary(overall_status: str, spf_result: dict, dkim_results: list, dmarc_result: dict, final_score: int, industry_score: int) -> str:
    """Generate a quick summary for immediate overview."""
    
    # Get status indicators
    spf_status = _get_industry_standard_status("spf", spf_result)
    dkim_status = _get_industry_standard_status("dkim", {}, dkim_results)
    dmarc_status = _get_industry_standard_status("dmarc", dmarc_result)
    
    # Count issues
    risky_count = sum(1 for status in [spf_status, dkim_status, dmarc_status] if status == "Risky")
    warning_count = sum(1 for status in [spf_status, dkim_status, dmarc_status] if status == "Warning")
    valid_count = sum(1 for status in [spf_status, dkim_status, dmarc_status] if status == "Valid")
    
    # Generate quick summary
    if overall_status == SecurityStatus.FAIL:  # high_risk
        summary = f"🔴 HIGH RISK - {risky_count} critical issues found"
    elif overall_status == SecurityStatus.WARNING:  # medium_risk
        summary = f"🟡 MEDIUM RISK - {warning_count} issues to address"
    else:  # SecurityStatus.PASS (low_risk)
        summary = f"🟢 LOW RISK - {valid_count} protocols properly configured"
    
    summary += f" | Score: {industry_score}/10"
    
    # Add quick protocol status
    summary += f"\nSPF: {spf_status.upper()} | DKIM: {dkim_status.upper()} | DMARC: {dmarc_status.upper()}"
    
    return summary

def _generate_protocol_status(spf_result: dict, dkim_results: list, dmarc_result: dict, 
                             mtasts_result: dict, tlsrpt_result: dict, bimi_result: dict, mx_result: dict) -> dict:
    """Generate detailed protocol status summary."""
    
    status_summary = {}
    
    # SPF Status
    if spf_result.get('exists', False):
        spf_status = "Configured"
        if spf_result.get('status') == 'pass':
            spf_status = "Properly Configured"
        elif spf_result.get('status') == 'warning':
            spf_status = "Partially Configured"
        else:
            spf_status = "Misconfigured"
    else:
        spf_status = "Missing"
    
    status_summary["spf"] = {
        "status": spf_status,
        "status_indicator": _get_industry_standard_status("spf", spf_result),
        "policy": spf_result.get('all_mechanism', 'Not specified'),
        "includes_count": len(spf_result.get('includes', [])),
        "record": spf_result.get('record', 'Not found')
    }
    
    # DKIM Status
    if dkim_results and any(dkim.get('exists', False) for dkim in dkim_results if dkim is not None):
        dkim_status = "Configured"
        passing_selectors = [dkim.get('selector') for dkim in dkim_results if dkim and dkim.get('status') == 'pass']
        if passing_selectors:
            dkim_status = "Properly Configured"
        else:
            dkim_status = "Partially Configured"
    else:
        dkim_status = "Missing"
    
    status_summary["dkim"] = {
        "status": dkim_status,
        "status_indicator": _get_industry_standard_status("dkim", {}, dkim_results),
        "selectors_checked": len(dkim_results or []),
        "working_selectors": len([dkim for dkim in (dkim_results or []) if dkim and dkim.get('status') == 'pass']),
        "key_strength": "Strong" if all(dkim.get('key_size', 0) >= 1024 for dkim in (dkim_results or []) if dkim and dkim.get('key_size')) else "Weak"
    }
    
    # DMARC Status
    if dmarc_result.get('exists', False):
        dmarc_policy = dmarc_result.get('policy', 'none')
        if dmarc_policy == 'reject':
            dmarc_status = "Properly Configured (Reject)"
        elif dmarc_policy == 'quarantine':
            dmarc_status = "Partially Configured (Quarantine)"
        else:
            dmarc_status = "Monitoring Only (None)"
    else:
        dmarc_status = "Missing"
    
    status_summary["dmarc"] = {
        "status": dmarc_status,
        "status_indicator": _get_industry_standard_status("dmarc", dmarc_result),
        "policy": dmarc_result.get('policy', 'Not configured'),
        "subdomain_policy": dmarc_result.get('subdomain_policy', 'Not configured'),
        "reporting": "Configured" if (dmarc_result.get('report_uri') or dmarc_result.get('forensic_uri')) else "Not configured"
    }
    
    # MTA-STS Status
    if mtasts_result.get('exists', False):
        mtasts_status = "Configured"
        if mtasts_result.get('status') == 'pass':
            mtasts_status = "Properly Configured"
        else:
            mtasts_status = "Partially Configured"
    else:
        mtasts_status = "Missing"
    
    status_summary["mtasts"] = {
        "status": mtasts_status,
        "mode": mtasts_result.get('mode', 'Not configured'),
        "policy_accessible": mtasts_result.get('policy_accessible', False)
    }
    
    # TLS-RPT Status
    if tlsrpt_result.get('exists', False):
        tlsrpt_status = "Configured"
        if tlsrpt_result.get('status') == 'pass':
            tlsrpt_status = "Properly Configured"
        else:
            tlsrpt_status = "Partially Configured"
    else:
        tlsrpt_status = "Missing"
    
    status_summary["tlsrpt"] = {
        "status": tlsrpt_status,
        "reporting_uris": len(tlsrpt_result.get('rua', []))
    }
    
    # BIMI Status
    if bimi_result.get('exists', False):
        bimi_status = "Configured"
        if bimi_result.get('status') == 'pass':
            bimi_status = "Properly Configured"
        else:
            bimi_status = "Partially Configured"
    else:
        bimi_status = "Missing"
    
    status_summary["bimi"] = {
        "status": bimi_status,
        "logo_accessible": bimi_result.get('logo_accessible', False),
        "vmc_valid": bimi_result.get('vmc_valid', False)
    }
    
    # MX Status
    mx_records = mx_result.get('records', [])
    if mx_records:
        mx_status = "Configured"
        if mx_result.get('security_score', 0) >= 5:
            mx_status = "Secure Configuration"
        elif mx_result.get('open_relay_risk', False):
            mx_status = "Security Issues Detected"
    else:
        mx_status = "Missing"
    
    status_summary["mx"] = {
        "status": mx_status,
        "record_count": len(mx_records),
        "security_score": mx_result.get('security_score', 0),
        "open_relay_risk": mx_result.get('open_relay_risk', False)
    }
    
    return status_summary

router = APIRouter(prefix="/api/v1/security", tags=["Security Checks"])


@router.get("/scan/{domain}", response_model=SuccessResponse)
async def scan_domain_security(
    domain: str,
    include_whois: bool = Query(True, description="Include WHOIS information"),
    include_geolocation: bool = Query(True, description="Include server geolocation"),
    include_threat_intel: bool = Query(True, description="Include threat intelligence"),
    dkim_selectors: str = Query("default,google,selector1,selector2,k1,mandrill,s1,s2", description="Comma-separated DKIM selectors")
):
    """
    Perform comprehensive security scan of a domain.
    
    This endpoint analyzes all major email security records including:
    - SPF (Sender Policy Framework)
    - DKIM (DomainKeys Identified Mail)
    - DMARC (Domain-based Message Authentication, Reporting & Conformance)
    - BIMI (Brand Indicators for Message Identification)
    - MTA-STS (Mail Transfer Agent Strict Transport Security)
    - TLS-RPT (TLS Reporting)
    - MX (Mail Exchange) records
    - TLS/STARTTLS configuration
    """
    try:
        # Validate domain
        domain = DomainValidator.normalize_domain(domain)
        
        # Perform all security checks directly using async methods
        # (Previous synchronous pre-check removed to prevent blocking)
        
        # Parse DKIM selectors
        if hasattr(dkim_selectors, 'split'):
            selectors = [s.strip() for s in dkim_selectors.split(",") if s.strip()]
        else:
            # Handle case where dkim_selectors is a Query object or other type
            selectors = ["default", "google", "selector1", "selector2", "k1", "mandrill", "s1", "s2"]
        
        # Perform all security checks
        # Perform all security checks in parallel
        results = await asyncio.gather(
            dns_service.get_spf_record(domain),
            dns_service.get_dkim_records(domain, selectors),
            dns_service.get_dmarc_record(domain),
            dns_service.get_bimi_record(domain),
            dns_service.get_mtasts_record(domain),
            dns_service.get_tlsrpt_record(domain),
            dns_service.get_mx_records(domain),
            return_exceptions=True
        )
        
        # Unpack results, handling potential exceptions
        spf_result = results[0] if not isinstance(results[0], Exception) else {}
        dkim_results = results[1] if not isinstance(results[1], Exception) else []
        dmarc_result = results[2] if not isinstance(results[2], Exception) else {}
        bimi_result = results[3] if not isinstance(results[3], Exception) else {}
        mtasts_result = results[4] if not isinstance(results[4], Exception) else {}
        tlsrpt_result = results[5] if not isinstance(results[5], Exception) else {}
        mx_result = results[6] if not isinstance(results[6], Exception) else {}
        
        # Ensure all results are dictionaries
        spf_result = spf_result or {}
        dkim_results = dkim_results or []
        dmarc_result = dmarc_result or {}
        bimi_result = bimi_result or {}
        mtasts_result = mtasts_result or {}
        tlsrpt_result = tlsrpt_result or {}
        mx_result = mx_result or {}
        
        # TLS check (placeholder for now)
        tls_result = {
            'mx_records': [],
            'starttls_support': {},
            'tls_version': {},
            'certificate_valid': {},
            'status': 'not_found',
            'warnings': ['TLS checking not yet implemented'],
            'recommendations': ['TLS checking will be available in a future update']
        }
        
        # Threat intelligence is now handled in parallel above
        
        # Initialize threat intelligence
        threat_intel = None
        
        # Get threat intelligence (blacklist checking)
        if include_threat_intel:
            try:
                from app.services.blacklist_service import blacklist_service
                threat_intel = await blacklist_service.check_domain_blacklists(domain)
            except Exception as e:
                print(f"Error getting threat intelligence: {str(e)}")
                threat_intel = None
        else:
            threat_intel = None
        
        # Get additional intelligence if requested
        whois_info = None
        geolocation_info = None
        
        if include_whois:
            try:
                from app.api.v1.intelligence import get_whois_info
                whois_response = await get_whois_info(domain)
                whois_info = whois_response.data
            except Exception as e:
                print(f"Error getting WHOIS info: {str(e)}")
                whois_info = None
        
        if include_geolocation:
            try:
                from app.api.v1.intelligence import get_geolocation_info
                geo_response = await get_geolocation_info(domain)
                geolocation_info = geo_response.data
            except HTTPException as e:
                print(f"Error getting geolocation info: {str(e)}")
                geolocation_info = None
            except Exception as e:
                print(f"Error getting geolocation info: {str(e)}")
                geolocation_info = None
        
        # Calculate security score using industry-standard 3-category scoring system
        # Based on Easy DMARC and other industry standards
        core_protocols_score = 0    # Core Protocols (SPF, DKIM, DMARC) - 70 points max
        policy_enforcement_score = 0 # Policy Enforcement - 20 points max  
        advanced_features_score = 0  # Advanced Features - 10 points max
        
        # === CATEGORY 1: Core Protocols (70 points) ===
        # This is the most important category - aligns with Easy DMARC's 10/10 scoring
        
        # SPF (25 points) - Core authentication protocol
        if spf_result and spf_result.get('status') == 'pass' or (spf_result and str(spf_result.get('status', '')) == 'pass'):
            core_protocols_score += 25
        elif spf_result and spf_result.get('status') == 'warning' or (spf_result and str(spf_result.get('status', '')) == 'warning'):
            core_protocols_score += 15
        elif spf_result and spf_result.get('status') == 'fail' or (spf_result and str(spf_result.get('status', '')) == 'fail'):
            core_protocols_score += 5
        
        # DKIM (25 points) - Core authentication protocol
        if dkim_results is None:
            dkim_has_records = False
            dkim_has_passing = False
            dkim_has_errors = False
        else:
            dkim_has_records = any(dkim.get('exists', False) for dkim in dkim_results if dkim is not None)
            dkim_has_passing = any(dkim.get('status') == 'pass' or str(dkim.get('status', '')) == 'pass' for dkim in dkim_results if dkim is not None)
            # Only count as errors if records exist but have error status (not not_found)
            dkim_has_errors = any(dkim.get('status') == 'error' and dkim.get('exists', False) for dkim in dkim_results if dkim is not None)
        
        if dkim_has_passing:
            core_protocols_score += 25
        elif dkim_has_records:
            core_protocols_score += 15
        elif dkim_has_errors:
            # If we have errors (timeouts), give partial credit as the domain might have DKIM
            core_protocols_score += 10
        else:
            core_protocols_score += 5
        
        # DMARC (20 points) - Core authentication protocol
        if dmarc_result and dmarc_result.get('status') == 'pass' or (dmarc_result and str(dmarc_result.get('status', '')) == 'pass'):
            # Check main policy - if it's 'none', treat as warning
            main_policy = dmarc_result.get('policy', 'none')
            if main_policy == 'none':
                core_protocols_score += 10  # Reduced from 20 due to main policy being none
            else:
                # Check subdomain policy - if it's 'none', reduce score
                subdomain_policy = dmarc_result.get('subdomain_policy', 'none')
                if subdomain_policy == 'none':
                    core_protocols_score += 15  # Reduced from 20 due to subdomain policy
                else:
                    core_protocols_score += 20
        elif dmarc_result and dmarc_result.get('status') == 'warning' or (dmarc_result and str(dmarc_result.get('status', '')) == 'warning'):
            core_protocols_score += 10
        elif dmarc_result and dmarc_result.get('status') == 'fail' or (dmarc_result and str(dmarc_result.get('status', '')) == 'fail'):
            core_protocols_score += 5
        
        # === CATEGORY 2: Policy Enforcement (20 points) ===
        # DMARC Policy Strictness (15 points)
        if dmarc_result and dmarc_result.get('exists'):
            policy = dmarc_result.get('policy', 'none')
            if policy == 'reject':
                policy_enforcement_score += 15
            elif policy == 'quarantine':
                policy_enforcement_score += 10
            elif policy == 'none':
                # Check if reporting is configured
                has_reporting = bool(dmarc_result.get('report_uri') or dmarc_result.get('forensic_uri'))
                if has_reporting:
                    policy_enforcement_score += 5
                else:
                    policy_enforcement_score += 0
        
        # SPF Mechanism Hygiene (5 points)
        if spf_result and spf_result.get('exists') and (spf_result.get('status') == 'pass' or str(spf_result.get('status', '')) == 'pass'):
            record = spf_result.get('record', '')
            if '+all' in record:
                policy_enforcement_score += 0  # Penalty for too permissive
            elif '~all' in record or '-all' in record:
                policy_enforcement_score += 5
            else:
                policy_enforcement_score += 2
        
        # === CATEGORY 3: Advanced Features (10 points) ===
        # These are bonus points for advanced security features
        
        # MTA-STS (4 points)
        if mtasts_result and mtasts_result.get('status') == 'pass' or (mtasts_result and str(mtasts_result.get('status', '')) == 'pass'):
            advanced_features_score += 4
        elif mtasts_result and mtasts_result.get('status') == 'warning' or (mtasts_result and str(mtasts_result.get('status', '')) == 'warning'):
            advanced_features_score += 2
        
        # TLS-RPT (3 points)
        if tlsrpt_result and tlsrpt_result.get('status') == 'pass' or (tlsrpt_result and str(tlsrpt_result.get('status', '')) == 'pass'):
            advanced_features_score += 3
        elif tlsrpt_result and tlsrpt_result.get('status') == 'warning' or (tlsrpt_result and str(tlsrpt_result.get('status', '')) == 'warning'):
            advanced_features_score += 1
        
        # BIMI (3 points) - Optional branding feature
        if bimi_result and bimi_result.get('status') == 'pass' or (bimi_result and str(bimi_result.get('status', '')) == 'pass'):
            advanced_features_score += 3
        elif bimi_result and bimi_result.get('status') == 'warning' or (bimi_result and str(bimi_result.get('status', '')) == 'warning'):
            advanced_features_score += 1
        
        # Calculate total score (100 points max)
        total_score = core_protocols_score + policy_enforcement_score + advanced_features_score
        
        # Calculate industry standard 10-point score
        industry_score = 0
        
        # SPF (3 points)
        if spf_result and spf_result.get('status') == 'pass':
            industry_score += 3
        elif spf_result and spf_result.get('status') == 'warning':
            industry_score += 2
        elif spf_result and spf_result.get('status') == 'fail':
            industry_score += 1
        
        # DKIM (3 points)
        if dkim_has_passing:
            industry_score += 3
        elif dkim_has_records:
            industry_score += 2
        elif dkim_has_errors:
            industry_score += 1
        
        # DMARC (4 points) - More weight for industry standard
        if dmarc_result and dmarc_result.get('status') == 'pass':
            # Check main policy - if it's 'none', treat as warning
            main_policy = dmarc_result.get('policy', 'none')
            if main_policy == 'none':
                industry_score += 2  # Reduced from 4 due to main policy being none
            else:
                # Check subdomain policy - if it's 'none', reduce score
                subdomain_policy = dmarc_result.get('subdomain_policy', 'none')
                if subdomain_policy == 'none':
                    industry_score += 3  # Reduced due to subdomain policy
                else:
                    industry_score += 4
        elif dmarc_result and dmarc_result.get('status') == 'warning':
            industry_score += 2
        elif dmarc_result and dmarc_result.get('status') == 'fail':
            industry_score += 1
        
        # Apply minimal penalties for critical security issues only
        penalties = 0
        penalty_details = []
        
        # Penalty for SPF +all (too permissive) - only if it's the only mechanism
        if spf_result and spf_result.get('exists') and '+all' in spf_result.get('record', '') and 'include:' not in spf_result.get('record', '') and 'ip4:' not in spf_result.get('record', ''):
            penalties += 5
            penalty_details.append({
                'type': 'spf_too_permissive',
                'description': 'SPF record uses only +all mechanism (allows any server)',
                'penalty': 5,
                'severity': 'medium'
            })
        
        # Penalty for DMARC none without reporting (only if no other protection)
        if dmarc_result and dmarc_result.get('exists'):
            policy = dmarc_result.get('policy', 'none')
            has_reporting = bool(dmarc_result.get('report_uri') or dmarc_result.get('forensic_uri'))
            if policy == 'none' and not has_reporting and not spf_result.get('exists'):
                penalties += 5
                penalty_details.append({
                    'type': 'dmarc_none_without_reporting',
                    'description': 'DMARC policy is none without reporting and no SPF protection',
                    'penalty': 5,
                    'severity': 'medium'
                })
        # Final score with special adjustments for industry-standard scoring
        final_score = total_score
        
        # Special adjustment: If domain has SPF and DMARC but DKIM has timeout issues,
        # give bonus points as this is common for properly configured domains
        if (spf_result and spf_result.get('status') == 'pass' and 
            dmarc_result and dmarc_result.get('status') == 'pass' and
            dkim_has_errors and not dkim_has_records):
            # This is likely a properly configured domain with DNS timeout issues
            final_score = min(100, final_score + 15)  # Bonus up to 15 points
        
        # Determine overall status based on score
        # Map score to SecurityStatus enum (pass/warning/fail)
        if final_score >= 90:
            overall_status = SecurityStatus.PASS  # Low risk = pass
        elif final_score >= 70:
            overall_status = SecurityStatus.WARNING  # Medium risk = warning
        else:
            overall_status = SecurityStatus.FAIL  # High risk = fail
        
        # Industry standard risk assessment
        if industry_score >= 8:
            industry_risk = 'low_risk'
        elif industry_score >= 6:
            industry_risk = 'medium_risk'
        else:
            industry_risk = 'high_risk'
        
        # Generate comprehensive risk assessment description
        risk_assessment = _generate_risk_assessment(overall_status, spf_result, dkim_results, dmarc_result, final_score)
        
        # Generate industry standard risk assessment
        industry_risk_assessment = _generate_industry_standard_risk_assessment(industry_score, industry_risk, spf_result, dkim_results, dmarc_result)
        
        # Generate detailed protocol status summary
        protocol_status = _generate_protocol_status(spf_result, dkim_results, dmarc_result, mtasts_result, tlsrpt_result, bimi_result, mx_result)
        
        # Generate human-readable summary text
        summary_text = _generate_summary_text(industry_risk, spf_result, dkim_results, dmarc_result, final_score, industry_score)
        
        # Generate quick summary
        quick_summary = _generate_quick_summary(industry_risk, spf_result, dkim_results, dmarc_result, final_score, industry_score)
        
        # Collect all warnings and recommendations
        all_warnings = []
        all_recommendations = []
        
        all_warnings.extend(spf_result.get('warnings', []) or [])
        all_warnings.extend(dmarc_result.get('warnings', []) or [])
        all_warnings.extend(mtasts_result.get('warnings', []) or [])
        all_warnings.extend(tlsrpt_result.get('warnings', []) or [])
        all_warnings.extend(mx_result.get('warnings', []) or [])
        all_warnings.extend(bimi_result.get('warnings', []) or [])
        all_warnings.extend(tls_result.get('warnings', []) or [])
        
        all_recommendations.extend(spf_result.get('recommendations', []) or [])
        all_recommendations.extend(dmarc_result.get('recommendations', []) or [])
        all_recommendations.extend(mtasts_result.get('recommendations', []) or [])
        all_recommendations.extend(tlsrpt_result.get('recommendations', []) or [])
        all_recommendations.extend(mx_result.get('recommendations', []) or [])
        all_recommendations.extend(bimi_result.get('recommendations', []) or [])
        all_recommendations.extend(tls_result.get('recommendations', []) or [])
        
        # Add DKIM warnings and recommendations
        if dkim_results is not None:
            for dkim in dkim_results:
                if dkim is None:
                    continue
                all_warnings.extend(dkim.get('warnings', []) or [])
                all_recommendations.extend(dkim.get('recommendations', []) or [])
        
        # Create summary
        summary = []
        if spf_result['exists']:
            summary.append("SPF record found")
        if dkim_results is not None and any(dkim.get('exists', False) for dkim in dkim_results if dkim is not None):
            summary.append("DKIM records found")
        if dmarc_result['exists']:
            summary.append("DMARC record found")
        if mtasts_result['exists']:
            summary.append("MTA-STS record found")
        if tlsrpt_result['exists']:
            summary.append("TLS-RPT record found")
        
        # Create detailed scoring breakdown for industry-standard 3-category system
        scoring_breakdown = {
            "industry_standard_10_point": {
                "total_points": 10,
                "earned_points": industry_score,
                "risk_level": industry_risk,
                "components": {
                    "spf": {
                        "max_points": 3,
                        "earned_points": 3 if (spf_result and spf_result.get('status') == 'pass') else (2 if (spf_result and spf_result.get('status') == 'warning') else 1),
                        "status": _get_industry_standard_status("spf", spf_result),
                        "technical_status": str(spf_result.get('status', 'not_found')) if spf_result else 'not_found'
                    },
                    "dkim": {
                        "max_points": 3,
                        "earned_points": 3 if dkim_has_passing else (2 if dkim_has_records else 1),
                        "status": _get_industry_standard_status("dkim", {}, dkim_results),
                        "technical_status": "pass" if dkim_has_passing else ("warning" if dkim_has_records else "fail")
                    },
                    "dmarc": {
                        "max_points": 4,
                        "earned_points": 4 if (dmarc_result and dmarc_result.get('status') == 'pass' and dmarc_result.get('subdomain_policy') != 'none') else (3 if (dmarc_result and dmarc_result.get('status') == 'pass') else (2 if (dmarc_result and dmarc_result.get('status') == 'warning') else 1)),
                        "status": _get_industry_standard_status("dmarc", dmarc_result),
                        "technical_status": str(dmarc_result.get('status', 'not_found')) if dmarc_result else 'not_found',
                        "subdomain_policy": dmarc_result.get('subdomain_policy', 'none') if dmarc_result else 'none'
                    }
                }
            },
            "core_protocols": {
                "total_points": 70,
                "earned_points": core_protocols_score,
                "components": {
                    "spf": {
                        "max_points": 25,
                        "earned_points": 25 if (spf_result and spf_result.get('status') == 'pass') else (15 if (spf_result and spf_result.get('status') == 'warning') else 5),
                        "status": str(spf_result.get('status', 'not_found')) if spf_result else 'not_found'
                    },
                    "dkim": {
                        "max_points": 25,
                        "earned_points": 25 if dkim_has_passing else (15 if dkim_has_records else 5),
                        "status": "pass" if dkim_has_passing else ("warning" if dkim_has_records else "fail")
                    },
                    "dmarc": {
                        "max_points": 20,
                        "earned_points": 20 if (dmarc_result and dmarc_result.get('status') == 'pass') else (10 if (dmarc_result and dmarc_result.get('status') == 'warning') else 5),
                        "status": str(dmarc_result.get('status', 'not_found')) if dmarc_result else 'not_found'
                    }
                }
            },
            "policy_enforcement": {
                "total_points": 20,
                "earned_points": policy_enforcement_score,
                "components": {
                    "dmarc_policy": {
                        "max_points": 15,
                        "earned_points": 15 if (dmarc_result and dmarc_result.get('policy') == 'reject') else (10 if (dmarc_result and dmarc_result.get('policy') == 'quarantine') else 5),
                        "policy": dmarc_result.get('policy', 'none') if dmarc_result else 'none'
                    },
                    "spf_hygiene": {
                        "max_points": 5,
                        "earned_points": 5 if (spf_result and spf_result.get('record') and ('~all' in spf_result.get('record', '') or '-all' in spf_result.get('record', ''))) else (0 if (spf_result and spf_result.get('record') and '+all' in spf_result.get('record', '')) else 2),
                        "mechanism": "~all" if (spf_result and spf_result.get('record') and '~all' in spf_result.get('record', '')) else ("-all" if (spf_result and spf_result.get('record') and '-all' in spf_result.get('record', '')) else ("+all" if (spf_result and spf_result.get('record') and '+all' in spf_result.get('record', '')) else "other"))
                    }
                }
            },
            "advanced_features": {
                "total_points": 10,
                "earned_points": advanced_features_score,
                "components": {
                    "mtasts": {
                        "max_points": 4,
                        "earned_points": 4 if (mtasts_result and mtasts_result.get('status') == 'pass') else (2 if (mtasts_result and mtasts_result.get('status') == 'warning') else 0),
                        "status": str(mtasts_result.get('status', 'not_found')) if mtasts_result else 'not_found'
                    },
                    "tlsrpt": {
                        "max_points": 3,
                        "earned_points": 3 if (tlsrpt_result and tlsrpt_result.get('status') == 'pass') else (1 if (tlsrpt_result and tlsrpt_result.get('status') == 'warning') else 0),
                        "status": str(tlsrpt_result.get('status', 'not_found')) if tlsrpt_result else 'not_found'
                    },
                    "bimi": {
                        "max_points": 3,
                        "earned_points": 3 if (bimi_result and bimi_result.get('status') == 'pass') else (1 if (bimi_result and bimi_result.get('status') == 'warning') else 0),
                        "status": str(bimi_result.get('status', 'not_found')) if bimi_result else 'not_found'
                    }
                }
            }
        }
        
        # Note: Penalties are already calculated above and included in penalty_details
        
        # Generate AI summary using GPT (single API call)
        ai_summary = None
        if gpt_summarizer.is_available():
            scan_data_for_summary = {
                "domain": domain,
                "score": final_score,
                "overall_status": overall_status,
                "recommendations": list(set([r for r in all_recommendations if r is not None])),
                "risk_assessment": risk_assessment,
                "summary": [s for s in summary if s is not None],
                "protocol_status": protocol_status,
                "scoring_breakdown": scoring_breakdown
            }
            ai_summary = gpt_summarizer.generate_summary(scan_data_for_summary)
        
        # Create result
        try:
            result = SecurityScanResult(
                domain=domain,
                scan_timestamp=datetime.now().isoformat(),
                overall_status=overall_status,
                spf=SPFRecord(**spf_result),
                dkim=[DKIMRecord(**dkim) for dkim in (dkim_results or []) if dkim is not None],
                dmarc=DMARCRecord(**dmarc_result),
                bimi=BIMIRecord(**bimi_result),
                mtasts=MTASTSRecord(**mtasts_result),
                tlsrpt=TLSRPTRecord(**tlsrpt_result),
                tls=TLSRecord(**tls_result),
                mx=MXRecord(**mx_result),
                score=final_score,
                overall_score=final_score,
                summary=[s for s in summary if s is not None],
                recommendations=list(set([r for r in all_recommendations if r is not None])),  # Remove duplicates and None values
                scoring_breakdown=scoring_breakdown,
                risk_assessment=risk_assessment,
                industry_standard_assessment=industry_risk_assessment,
                protocol_status=protocol_status,
                summary_text=summary_text,
                quick_summary=quick_summary,
                ai_summary=ai_summary
            )
        except Exception as model_error:
            # If model creation fails, return a simplified response
            print(f"Model creation error: {str(model_error)}")
            return SuccessResponse(
                success=True,
                message="Security scan completed with simplified results",
                data={
                    "domain": domain,
                    "scan_timestamp": datetime.now().isoformat(),
                    "overall_status": overall_status,
                    "score": final_score,
                    "overall_score": final_score,
                    "summary": [s for s in summary if s is not None],
                    "recommendations": list(set([r for r in all_recommendations if r is not None])),
                    "scoring_breakdown": scoring_breakdown,
                    "risk_assessment": risk_assessment,
                    "industry_standard_assessment": industry_risk_assessment,
                    "protocol_status": protocol_status,
                    "summary_text": summary_text,
                    "quick_summary": quick_summary,
                    "ai_summary": ai_summary,
                    "error": "Some security records could not be processed due to missing or invalid data"
                }
            )
        
        return SuccessResponse(
            success=True,
            message="Security scan completed successfully",
            data=result
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error performing security scan: {str(e)}")


@router.get("/spf/{domain}", response_model=SuccessResponse)
async def check_spf_record(domain: str = Path(..., description="Domain name to check", example="example.com")):
    """
    Check SPF (Sender Policy Framework) record for a domain.
    
    SPF helps prevent email spoofing by specifying which servers are authorized
    to send email on behalf of the domain.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        result = await dns_service.get_spf_record(domain)
        
        return SuccessResponse(
            success=True,
            message="SPF check completed",
            data=SPFRecord(**result)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking SPF record: {str(e)}")


@router.get("/dkim/{domain}", response_model=SuccessResponse)
async def check_dkim_records(
    domain: str = Path(..., description="Domain name to check", example="example.com"),
    selectors: str = Query("default,google,selector1,selector2,k1,mandrill,s1,s2", description="Comma-separated DKIM selectors")
):
    """
    Check DKIM (DomainKeys Identified Mail) records for a domain.
    
    DKIM adds a digital signature to emails to verify they haven't been tampered with
    during transit.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        selectors_list = [s.strip() for s in selectors.split(",") if s.strip()]
        results = await dns_service.get_dkim_records(domain, selectors_list)
        
        return SuccessResponse(
            success=True,
            message="DKIM check completed",
            data=[DKIMRecord(**result) for result in results]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking DKIM records: {str(e)}")


@router.get("/dmarc/{domain}", response_model=SuccessResponse)
async def check_dmarc_record(domain: str = Path(..., description="Domain name to check", example="example.com")):
    """
    Check DMARC (Domain-based Message Authentication, Reporting & Conformance) record for a domain.
    
    DMARC provides a policy framework for email authentication and reporting.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        result = await dns_service.get_dmarc_record(domain)
        
        return SuccessResponse(
            success=True,
            message="DMARC check completed",
            data=DMARCRecord(**result)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking DMARC record: {str(e)}")


@router.get("/mtasts/{domain}", response_model=SuccessResponse)
async def check_mtasts_record(domain: str = Path(..., description="Domain name to check", example="example.com")):
    """
    Check MTA-STS (Mail Transfer Agent Strict Transport Security) record for a domain.
    
    MTA-STS protects against downgrade attacks on SMTP connections by enforcing
    TLS encryption for email delivery.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        result = await dns_service.get_mtasts_record(domain)
        
        return SuccessResponse(
            success=True,
            message="MTA-STS check completed",
            data=MTASTSRecord(**result)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking MTA-STS record: {str(e)}")


@router.get("/tlsrpt/{domain}", response_model=SuccessResponse)
async def check_tlsrpt_record(domain: str = Path(..., description="Domain name to check", example="example.com")):
    """
    Check TLS-RPT (TLS Reporting) record for a domain.
    
    TLS-RPT provides reporting on TLS failures for email delivery, helping to
    identify and resolve encryption issues.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        result = await dns_service.get_tlsrpt_record(domain)
        
        return SuccessResponse(
            success=True,
            message="TLS-RPT check completed",
            data=TLSRPTRecord(**result)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking TLS-RPT record: {str(e)}")


@router.get("/bimi/{domain}", response_model=SuccessResponse)
async def check_bimi_record(domain: str = Path(..., description="Domain name to check", example="example.com")):
    """
    Check BIMI (Brand Indicators for Message Identification) record for a domain.
    
    BIMI allows organizations to display their logo in email clients, improving
    brand recognition and trust.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        result = await dns_service.get_bimi_record(domain)
        
        return SuccessResponse(
            success=True,
            message="BIMI check completed",
            data=BIMIRecord(**result)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking BIMI record: {str(e)}")


@router.get("/tls/{domain}", response_model=SuccessResponse)
async def check_tls_configuration(domain: str = Path(..., description="Domain name to check", example="example.com")):
    """
    Check TLS/STARTTLS configuration for mail servers.
    
    This endpoint analyzes the TLS configuration of mail servers to ensure
    secure email transmission.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        
        # Placeholder implementation
        result = {
            'mx_records': [],
            'starttls_support': {},
            'tls_version': {},
            'certificate_valid': {},
            'status': 'not_found',
            'warnings': ['TLS checking not yet implemented'],
            'recommendations': ['TLS checking will be available in a future update']
        }
        
        return SuccessResponse(
            success=True,
            message="TLS check completed",
            data=TLSRecord(**result)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking TLS configuration: {str(e)}")


@router.get("/dnssec/{domain}", response_model=SuccessResponse)
async def check_dnssec_status(domain: str = Path(..., description="Domain name to check", example="example.com")):
    """
    Check DNSSEC (DNS Security Extensions) status for a domain.
    
    DNSSEC provides DNS authentication and integrity to prevent DNS spoofing and cache poisoning attacks.
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        result = await dns_service.get_dnssec_status(domain)
        
        return SuccessResponse(
            success=True,
            message="DNSSEC check completed",
            data=DNSSECRecord(**result)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking DNSSEC status: {str(e)}")


@router.get("/mx/{domain}", response_model=SuccessResponse)
async def get_mx_records(domain: str):
    """
    Get and analyze MX records for a domain.
    
    Args:
        domain: Domain name to check
        
    Returns:
        MX record analysis
    """
    try:
        domain = DomainValidator.normalize_domain(domain)
        result = await dns_service.get_mx_records(domain)
        
        return SuccessResponse(
            success=True,
            message=f"MX records retrieved for {domain}",
            data=result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reverse-dns/{ip_address}")
async def get_reverse_dns(
    ip_address: str = Path(..., description="IP address to lookup")
):
    """
    Perform reverse DNS (PTR) lookup for an IP address.
    
    Args:
        ip_address: IP address to lookup
        
    Returns:
        Reverse DNS lookup result including hostname and forward confirmation
    """
    try:
        result = await dns_service.get_reverse_dns(ip_address)
        
        return SuccessResponse(
            success=True,
            message=f"Reverse DNS lookup completed for {ip_address}",
            data=result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/port-scan/{hostname}")
async def scan_mail_ports(
    hostname: str = Path(..., description="Hostname or IP address to scan"),
    timeout: float = Query(3.0, description="Connection timeout in seconds", ge=0.5, le=10.0)
):
    """
    Scan common mail server ports (SMTP, IMAP, POP3) for a hostname.
    
    Args:
        hostname: Hostname or IP address to scan
        timeout: Connection timeout in seconds (default: 3.0)
        
    Returns:
        Port scan results showing which mail ports are open/closed
    """
    try:
        result = await dns_service.scan_mail_ports(hostname, timeout)
        
        return SuccessResponse(
            success=True,
            message=f"Port scan completed for {hostname}",
            data=result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blacklist-check/{ip_address}")
async def check_blacklists(
    ip_address: str = Path(..., description="IP address to check against RBLs"),
    timeout: float = Query(2.0, description="DNS query timeout in seconds", ge=0.5, le=5.0)
):
    """
    Check if an IP address is listed on multiple RBL (Real-time Blackhole List) providers.
    
    Checks against major RBL providers including:
    - Spamhaus ZEN
    - SpamCop
    - Barracuda
    - SORBS
    - PSBL
    - UCEPROTECT
    - CBL (Composite Blocking List)
    - DroneBL
    
    Args:
        ip_address: IP address to check
        timeout: DNS query timeout in seconds (default: 2.0)
        
    Returns:
        Blacklist check results with detailed status per RBL provider
    """
    try:
        result = await dns_service.check_blacklists(ip_address, timeout)
        
        return SuccessResponse(
            success=True,
            message=f"Blacklist check completed for {ip_address}",
            data=result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))