from fastapi import APIRouter, HTTPException, Path, Query
import whois
import requests
from typing import Optional
from datetime import datetime

from app.models.responses import SuccessResponse, WHOISInfo, GeolocationInfo, ThreatIntelligence, BlacklistResult
from app.utils.validation_utils import DomainValidator
from app.config import settings

router = APIRouter(prefix="/api/v1/intelligence", tags=["Intelligence"])


@router.get("/whois/{domain}", response_model=SuccessResponse)
async def get_whois_info(
    domain: str = Path(..., description="Domain name to lookup", example="example.com")
):
    """
    Get WHOIS information for a domain.
    
    Retrieves domain registration details including registrar, creation date,
    expiration date, name servers, and DNSSEC status.
    """
    try:
        # Validate domain
        if not DomainValidator.is_valid_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        
        # Normalize domain
        domain = DomainValidator.normalize_domain(domain)
        
        # Get WHOIS information
        try:
            w = whois.whois(domain)
        except Exception as e:
            return SuccessResponse(
                message="WHOIS lookup failed",
                data={
                    "domain": domain,
                    "registrar": None,
                    "creation_date": None,
                    "expiration_date": None,
                    "updated_date": None,
                    "status": [],
                    "name_servers": [],
                    "dnssec": None,
                    "error": f"WHOIS lookup failed: {str(e)}"
                }
            )
        
        # Parse WHOIS data with safe handling of None values and mixed types
        def safe_list(value):
            if value is None:
                return []
            elif isinstance(value, (list, set, tuple)):
                return [str(v) for v in value if v is not None]
            else:
                return [str(value)] if value else []
        
        def safe_date(value):
            # Only accept datetime instances; ignore strings/dates to avoid validation errors
            if value is None:
                return None
            if isinstance(value, list):
                for v in value:
                    if isinstance(v, datetime):
                        return v
                return None
            return value if isinstance(value, datetime) else None
        
        # dnssec can be boolean, string, or missing depending on WHOIS source
        dnssec_value = None
        if hasattr(w, 'dnssec'):
            val = getattr(w, 'dnssec')
            if isinstance(val, (bool, str)):
                dnssec_value = val
            else:
                dnssec_value = None
        
        whois_info = WHOISInfo(
            domain=domain,
            registrar=w.registrar,
            creation_date=safe_date(w.creation_date),
            expiration_date=safe_date(w.expiration_date),
            updated_date=safe_date(w.updated_date),
            status=safe_list(w.status),
            name_servers=safe_list(w.name_servers),
            dnssec=dnssec_value
        )
        
        return SuccessResponse(
            message="WHOIS information retrieved successfully",
            data=whois_info
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving WHOIS information: {str(e)}")


@router.get("/geolocation/{domain}", response_model=SuccessResponse)
async def get_geolocation_info(
    domain: str = Path(..., description="Domain name to lookup", example="example.com")
):
    """
    Get geolocation information for a domain's mail servers.
    
    Retrieves IP geolocation data including country, region, city,
    coordinates, timezone, and ISP information.
    """
    try:
        # Validate domain
        if not DomainValidator.is_valid_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        
        # Normalize domain
        domain = DomainValidator.normalize_domain(domain)
        
        # Get MX records to find mail servers
        from app.services.dns_service import dns_service
        mx_result = await dns_service.get_mx_records(domain)
        
        if not mx_result or not mx_result.get('records'):
            return SuccessResponse(
                message="No MX records found for domain",
                data={
                    "domain": domain,
                    "mail_servers": [],
                    "count": 0,
                    "error": "No MX records found for domain"
                }
            )
        
        # Get IP addresses for MX servers
        from app.utils.dns_utils import dns_resolver
        geolocation_data = []
        
        for mx_record in mx_result.get('records', []):
            mx_server = mx_record.get('exchange')
            if not mx_server:
                continue
            
            try:
                # Resolve IP address
                a_records = dns_resolver.resolve_a(mx_server)
                if not a_records:
                    continue
                
                ip_address = a_records[0]
                
                # Get geolocation data
                geo_info = await _get_ip_geolocation(ip_address)
                if geo_info:
                    # Convert Pydantic model to dict and add additional fields
                    geo_info_dict = geo_info.model_dump()
                    geo_info_dict['mx_server'] = mx_server
                    geo_info_dict['ip_address'] = ip_address
                    geolocation_data.append(geo_info_dict)
                    
            except Exception as e:
                # Continue with other servers if one fails
                continue
        
        if not geolocation_data:
            return SuccessResponse(
                message="Could not retrieve geolocation data for any mail servers",
                data={
                    "domain": domain,
                    "mail_servers": [],
                    "count": 0,
                    "error": "Could not retrieve geolocation data for any mail servers"
                }
            )
        
        return SuccessResponse(
            message="Geolocation information retrieved successfully",
            data={
                "domain": domain,
                "mail_servers": geolocation_data,
                "count": len(geolocation_data)
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving geolocation information: {str(e)}")


@router.get("/threat/{domain}", response_model=SuccessResponse)
async def get_threat_intelligence(
    domain: str = Path(..., description="Domain name to check", example="example.com")
):
    """
    Get comprehensive threat intelligence for a domain.
    
    Checks the domain against multiple reputable blacklists and provides detailed reputation analysis.
    Returns blacklist status, reputation score, risk assessment, and detailed breakdown.
    """
    try:
        # Validate domain
        if not DomainValidator.is_valid_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        
        # Normalize domain
        domain = DomainValidator.normalize_domain(domain)
        
        # Import blacklist service
        from app.services.blacklist_service import blacklist_service
        
        # Check domain against blacklists
        blacklist_result = await blacklist_service.check_domain_blacklists(domain)
        
        # Convert to ThreatIntelligence model
        threat_info = ThreatIntelligence(
            domain=blacklist_result['domain'],
            ip_address=blacklist_result['ip_address'],
            blacklisted=blacklist_result['blacklisted'],
            blacklist_count=blacklist_result['blacklist_count'],
            reputation_score=blacklist_result['reputation_score'],
            risk_level=blacklist_result['risk_level'],
            blacklists=[BlacklistResult(**bl) for bl in blacklist_result['blacklists']],
            summary=blacklist_result['summary'],
            timestamp=blacklist_result['timestamp'],
            last_seen=None,  # Not implemented yet
            categories=[],   # Not implemented yet
            details={
                "total_blacklists_checked": len(blacklist_result['blacklists']),
                "successful_checks": len([bl for bl in blacklist_result['blacklists'] if bl['error'] is None]),
                "high_severity_listings": len([bl for bl in blacklist_result['blacklists'] if bl['listed'] and bl['severity'] == 'high']),
                "medium_severity_listings": len([bl for bl in blacklist_result['blacklists'] if bl['listed'] and bl['severity'] == 'medium'])
            }
        )
        
        return SuccessResponse(
            message="Threat intelligence check completed",
            data=threat_info
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving threat intelligence: {str(e)}")


async def _get_ip_geolocation(ip_address: str) -> Optional[GeolocationInfo]:
    """
    Get geolocation information for an IP address.
    
    Args:
        ip_address: IP address to lookup
        
    Returns:
        GeolocationInfo object or None if lookup fails
    """
    try:
        # Use IPInfo if token is available
        if settings.ipinfo_token:
            url = f"https://ipinfo.io/{ip_address}/json?token={settings.ipinfo_token}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse coordinates
                coords = data.get('loc', '').split(',')
                latitude = float(coords[0]) if len(coords) > 0 and coords[0] else None
                longitude = float(coords[1]) if len(coords) > 1 and coords[1] else None
                
                return GeolocationInfo(
                    ip=ip_address,
                    country=data.get('country'),
                    region=data.get('region'),
                    city=data.get('city'),
                    latitude=latitude,
                    longitude=longitude,
                    timezone=data.get('timezone'),
                    isp=data.get('org'),
                    org=data.get('org')
                )
        
        # Fallback to free IPInfo service (limited data)
        url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Parse coordinates
            coords = data.get('loc', '').split(',')
            latitude = float(coords[0]) if len(coords) > 0 and coords[0] else None
            longitude = float(coords[1]) if len(coords) > 1 and coords[1] else None
            
            return GeolocationInfo(
                ip=ip_address,
                country=data.get('country'),
                region=data.get('region'),
                city=data.get('city'),
                latitude=latitude,
                longitude=longitude,
                timezone=data.get('timezone'),
                isp=data.get('org'),
                org=data.get('org')
            )
        
        return None
        
    except Exception:
        return None


@router.get("/blacklists/info", response_model=SuccessResponse)
async def get_blacklist_information():
    """
    Get information about available blacklists.
    
    Returns details about all blacklists used for threat intelligence checking,
    including categories, severity levels, and descriptions.
    """
    try:
        from app.services.blacklist_service import blacklist_service
        
        blacklist_info = await blacklist_service.get_blacklist_info()
        
        return SuccessResponse(
            message="Blacklist information retrieved successfully",
            data=blacklist_info
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving blacklist information: {str(e)}")


@router.get("/threat/{domain}/detailed", response_model=SuccessResponse)
async def get_detailed_threat_intelligence(
    domain: str = Path(..., description="Domain name to check", example="example.com"),
    include_false_positives: bool = Query(False, description="Include known false positives in results")
):
    """
    Get detailed threat intelligence for a domain with configurable false positive handling.
    
    This endpoint allows you to control whether known false positives (like SPFBL 127.0.0.4)
    should be included in the results or ignored.
    """
    try:
        # Validate domain
        if not DomainValidator.is_valid_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        
        # Normalize domain
        domain = DomainValidator.normalize_domain(domain)
        
        # Import blacklist service
        from app.services.blacklist_service import blacklist_service
        
        # Temporarily modify the false positive setting
        original_setting = blacklist_service.ignore_false_positives
        blacklist_service.ignore_false_positives = not include_false_positives
        
        try:
            # Check domain against blacklists
            blacklist_result = await blacklist_service.check_domain_blacklists(domain)
            
            # Convert to ThreatIntelligence model
            threat_info = ThreatIntelligence(
                domain=blacklist_result['domain'],
                ip_address=blacklist_result['ip_address'],
                blacklisted=blacklist_result['blacklisted'],
                blacklist_count=blacklist_result['blacklist_count'],
                reputation_score=blacklist_result['reputation_score'],
                risk_level=blacklist_result['risk_level'],
                blacklists=[BlacklistResult(**bl) for bl in blacklist_result['blacklists']],
                summary=blacklist_result['summary'],
                timestamp=blacklist_result['timestamp'],
                last_seen=None,  # Not implemented yet
                categories=[],   # Not implemented yet
                details={
                    "total_blacklists_checked": len(blacklist_result['blacklists']),
                    "successful_checks": len([bl for bl in blacklist_result['blacklists'] if bl['error'] is None]),
                    "high_severity_listings": len([bl for bl in blacklist_result['blacklists'] if bl['listed'] and bl['severity'] == 'high']),
                    "medium_severity_listings": len([bl for bl in blacklist_result['blacklists'] if bl['listed'] and bl['severity'] == 'medium']),
                    "false_positives_ignored": not include_false_positives,
                    "configuration": {
                        "include_false_positives": include_false_positives,
                        "ignore_false_positives": not include_false_positives
                    }
                }
            )
            
            return SuccessResponse(
                message="Detailed threat intelligence check completed",
                data=threat_info
            )
            
        finally:
            # Restore original setting
            blacklist_service.ignore_false_positives = original_setting
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving detailed threat intelligence: {str(e)}")


@router.get("/dns/{domain}", response_model=SuccessResponse)
async def get_dns_records(
    domain: str = Path(..., description="Domain name to check", example="example.com")
):
    """
    Get comprehensive DNS records for a domain.
    
    Retrieves all major DNS record types including A, AAAA, MX, NS, TXT, and CNAME records.
    """
    try:
        # Validate domain
        if not DomainValidator.is_valid_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        
        # Normalize domain
        domain = DomainValidator.normalize_domain(domain)
        
        # Get DNS records
        from app.utils.dns_utils import dns_resolver
        
        a_records = dns_resolver.resolve_a(domain)
        aaaa_records = dns_resolver.resolve_aaaa(domain)
        mx_records = dns_resolver.resolve_mx(domain)
        ns_records = dns_resolver.resolve_ns(domain)
        txt_records = dns_resolver.resolve_txt(domain)
        txt_timeout = txt_records is None
        if txt_records is None:
            txt_records = []

        dns_data = {
            "domain": domain,
            "a_records": a_records,
            "aaaa_records": aaaa_records,
            "mx_records": mx_records,
            "ns_records": ns_records,
            "txt_records": txt_records,
            "txt_timeout": txt_timeout,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return SuccessResponse(
            message="DNS records retrieved successfully",
            data=dns_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving DNS records: {str(e)}") 