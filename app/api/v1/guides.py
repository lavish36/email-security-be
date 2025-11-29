from fastapi import APIRouter, HTTPException, Path
from typing import List, Dict, Any

from app.models.responses import SuccessResponse, DNSProviderInfo, DNSProviderGuide

router = APIRouter(prefix="/api/v1/guides", tags=["DNS Guides"])


@router.get("/providers", response_model=SuccessResponse)
async def get_dns_providers():
    """
    Get list of available DNS providers.
    
    Returns information about supported DNS providers including
    their features, supported record types, and setup guides.
    """
    try:
        providers = [
            DNSProviderInfo(
                name="Cloudflare",
                slug="cloudflare",
                website="https://cloudflare.com",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS", "PTR"],
                description="Popular DNS provider with free tier, DDoS protection, and global CDN"
            ),
            DNSProviderInfo(
                name="GoDaddy",
                slug="godaddy",
                website="https://godaddy.com",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS", "PTR"],
                description="Domain registrar and DNS provider with comprehensive domain management"
            ),
            DNSProviderInfo(
                name="AWS Route53",
                slug="route53",
                website="https://aws.amazon.com/route53/",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS", "PTR", "ALIAS"],
                description="Amazon's cloud DNS service with high availability and scalability"
            ),
            DNSProviderInfo(
                name="Google Cloud DNS",
                slug="google-cloud-dns",
                website="https://cloud.google.com/dns",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS", "PTR"],
                description="Google's cloud DNS service with global infrastructure"
            ),
            DNSProviderInfo(
                name="Namecheap",
                slug="namecheap",
                website="https://namecheap.com",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS", "PTR"],
                description="Domain registrar with free DNS management and privacy protection"
            ),
            DNSProviderInfo(
                name="Hostinger",
                slug="hostinger",
                website="https://hostinger.com",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS", "PTR"],
                description="Web hosting provider with integrated DNS management"
            ),
            DNSProviderInfo(
                name="DigitalOcean",
                slug="digitalocean",
                website="https://digitalocean.com",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS", "PTR"],
                description="Cloud infrastructure provider with managed DNS service"
            ),
            DNSProviderInfo(
                name="Vercel",
                slug="vercel",
                website="https://vercel.com",
                supported_records=["A", "AAAA", "CNAME", "MX", "TXT", "SPF", "DKIM", "DMARC", "NS"],
                description="Frontend deployment platform with integrated DNS management"
            )
        ]
        
        return SuccessResponse(
            message="DNS providers retrieved successfully",
            data={
                "providers": providers,
                "count": len(providers),
                "note": "Use provider slugs to get detailed setup guides"
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving DNS providers: {str(e)}")


@router.get("/{provider}", response_model=SuccessResponse)
async def get_provider_guide(
    provider: str = Path(..., description="DNS provider slug", example="cloudflare")
):
    """
    Get detailed setup guide for a specific DNS provider.
    
    Returns step-by-step instructions for configuring DNS records
    including SPF, DKIM, and DMARC setup.
    """
    try:
        provider_guides = {
            "cloudflare": DNSProviderGuide(
                provider="Cloudflare",
                steps=[
                    {
                        "step": 1,
                        "title": "Access DNS Settings",
                        "description": "Log into your Cloudflare account and select your domain",
                        "instructions": [
                            "Go to https://dash.cloudflare.com",
                            "Click on your domain name",
                            "Navigate to the 'DNS' tab in the left sidebar"
                        ]
                    },
                    {
                        "step": 2,
                        "title": "Add SPF Record",
                        "description": "Create a TXT record for SPF",
                        "instructions": [
                            "Click 'Add record'",
                            "Type: TXT",
                            "Name: @ (or your domain name)",
                            "Content: v=spf1 include:_spf.google.com ~all",
                            "TTL: Auto",
                            "Click 'Save'"
                        ]
                    },
                    {
                        "step": 3,
                        "title": "Add DKIM Record",
                        "description": "Create a TXT record for DKIM",
                        "instructions": [
                            "Click 'Add record'",
                            "Type: TXT",
                            "Name: selector._domainkey (replace 'selector' with your DKIM selector)",
                            "Content: v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY",
                            "TTL: Auto",
                            "Click 'Save'"
                        ]
                    },
                    {
                        "step": 4,
                        "title": "Add DMARC Record",
                        "description": "Create a TXT record for DMARC",
                        "instructions": [
                            "Click 'Add record'",
                            "Type: TXT",
                            "Name: _dmarc",
                            "Content: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                            "TTL: Auto",
                            "Click 'Save'"
                        ]
                    }
                ],
                screenshots=[
                    "https://example.com/cloudflare-dns-settings.png",
                    "https://example.com/cloudflare-add-record.png"
                ],
                tips=[
                    "Use the 'Proxy status' toggle to enable Cloudflare's proxy for A records",
                    "Set TTL to 'Auto' for automatic optimization",
                    "Use the 'Import' feature to bulk import DNS records"
                ],
                common_issues=[
                    "DNS propagation can take up to 48 hours",
                    "Ensure you're not duplicating existing records",
                    "Check that record names match exactly (case-sensitive)"
                ]
            ),
            "godaddy": DNSProviderGuide(
                provider="GoDaddy",
                steps=[
                    {
                        "step": 1,
                        "title": "Access DNS Management",
                        "description": "Log into your GoDaddy account and access DNS settings",
                        "instructions": [
                            "Go to https://godaddy.com and sign in",
                            "Click 'My Products'",
                            "Find your domain and click 'DNS'",
                            "Click 'Manage DNS'"
                        ]
                    },
                    {
                        "step": 2,
                        "title": "Add SPF Record",
                        "description": "Create a TXT record for SPF",
                        "instructions": [
                            "Click 'Add' in the Records section",
                            "Type: TXT",
                            "Host: @",
                            "Value: v=spf1 include:_spf.google.com ~all",
                            "TTL: 1 Hour",
                            "Click 'Save'"
                        ]
                    },
                    {
                        "step": 3,
                        "title": "Add DKIM Record",
                        "description": "Create a TXT record for DKIM",
                        "instructions": [
                            "Click 'Add' in the Records section",
                            "Type: TXT",
                            "Host: selector._domainkey (replace 'selector' with your DKIM selector)",
                            "Value: v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY",
                            "TTL: 1 Hour",
                            "Click 'Save'"
                        ]
                    },
                    {
                        "step": 4,
                        "title": "Add DMARC Record",
                        "description": "Create a TXT record for DMARC",
                        "instructions": [
                            "Click 'Add' in the Records section",
                            "Type: TXT",
                            "Host: _dmarc",
                            "Value: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                            "TTL: 1 Hour",
                            "Click 'Save'"
                        ]
                    }
                ],
                screenshots=[
                    "https://example.com/godaddy-dns-management.png",
                    "https://example.com/godaddy-add-record.png"
                ],
                tips=[
                    "Use the 'Bulk Edit' feature for multiple records",
                    "Set TTL to 1 Hour for faster propagation",
                    "Use the 'Import' feature for bulk DNS management"
                ],
                common_issues=[
                    "DNS changes may take 24-48 hours to propagate",
                    "Ensure record names don't have trailing dots",
                    "Check that you're editing the correct domain"
                ]
            ),
            "route53": DNSProviderGuide(
                provider="AWS Route53",
                steps=[
                    {
                        "step": 1,
                        "title": "Access Hosted Zone",
                        "description": "Navigate to your Route53 hosted zone",
                        "instructions": [
                            "Go to AWS Console and navigate to Route53",
                            "Click 'Hosted zones' in the left sidebar",
                            "Click on your domain's hosted zone"
                        ]
                    },
                    {
                        "step": 2,
                        "title": "Add SPF Record",
                        "description": "Create a TXT record for SPF",
                        "instructions": [
                            "Click 'Create record'",
                            "Record type: TXT",
                            "Record name: Leave empty (for root domain)",
                            "Value: v=spf1 include:_spf.google.com ~all",
                            "TTL: 300",
                            "Click 'Create records'"
                        ]
                    },
                    {
                        "step": 3,
                        "title": "Add DKIM Record",
                        "description": "Create a TXT record for DKIM",
                        "instructions": [
                            "Click 'Create record'",
                            "Record type: TXT",
                            "Record name: selector._domainkey (replace 'selector' with your DKIM selector)",
                            "Value: v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY",
                            "TTL: 300",
                            "Click 'Create records'"
                        ]
                    },
                    {
                        "step": 4,
                        "title": "Add DMARC Record",
                        "description": "Create a TXT record for DMARC",
                        "instructions": [
                            "Click 'Create record'",
                            "Record type: TXT",
                            "Record name: _dmarc",
                            "Value: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                            "TTL: 300",
                            "Click 'Create records'"
                        ]
                    }
                ],
                screenshots=[
                    "https://example.com/route53-hosted-zone.png",
                    "https://example.com/route53-create-record.png"
                ],
                tips=[
                    "Use Route53's health checks for monitoring",
                    "Set up DNS failover for high availability",
                    "Use the AWS CLI for bulk DNS management"
                ],
                common_issues=[
                    "Ensure you have proper IAM permissions",
                    "Check that hosted zone is properly configured",
                    "Verify record names match exactly"
                ]
            )
        }
        
        if provider not in provider_guides:
            raise HTTPException(status_code=404, detail=f"Guide not found for provider: {provider}")
        
        return SuccessResponse(
            message=f"Setup guide retrieved successfully for {provider_guides[provider].provider}",
            data=provider_guides[provider]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving provider guide: {str(e)}")


@router.get("/{provider}/spf", response_model=SuccessResponse)
async def get_provider_spf_guide(
    provider: str = Path(..., description="DNS provider slug", example="cloudflare")
):
    """
    Get SPF-specific setup guide for a DNS provider.
    
    Returns detailed instructions for configuring SPF records
    with provider-specific steps and screenshots.
    """
    try:
        spf_guides = {
            "cloudflare": {
                "provider": "Cloudflare",
                "steps": [
                    "Log into your Cloudflare dashboard",
                    "Select your domain",
                    "Go to DNS settings",
                    "Add a new TXT record",
                    "Set name to @ (or your domain)",
                    "Set value to your SPF record",
                    "Set TTL to Auto",
                    "Save the record"
                ],
                "tips": [
                    "Use Cloudflare's proxy for A records when possible",
                    "Set TTL to Auto for optimal performance",
                    "Verify the record appears in DNS lookup tools"
                ]
            },
            "godaddy": {
                "provider": "GoDaddy",
                "steps": [
                    "Log into your GoDaddy account",
                    "Go to My Products > DNS",
                    "Click Manage DNS",
                    "Add a new TXT record",
                    "Set Host to @",
                    "Set Value to your SPF record",
                    "Set TTL to 1 Hour",
                    "Save the record"
                ],
                "tips": [
                    "Use the bulk edit feature for multiple records",
                    "Set TTL to 1 Hour for faster propagation",
                    "Check record propagation using online tools"
                ]
            },
            "route53": {
                "provider": "AWS Route53",
                "steps": [
                    "Go to AWS Route53 console",
                    "Select your hosted zone",
                    "Click Create Record",
                    "Select TXT record type",
                    "Leave Record name empty (for root domain)",
                    "Set Value to your SPF record",
                    "Set TTL to 300",
                    "Create the record"
                ],
                "tips": [
                    "Use AWS CLI for bulk operations",
                    "Set up health checks for monitoring",
                    "Consider using Route53's failover features"
                ]
            }
        }
        
        if provider not in spf_guides:
            raise HTTPException(status_code=404, detail=f"SPF guide not found for provider: {provider}")
        
        return SuccessResponse(
            message=f"SPF setup guide retrieved successfully for {spf_guides[provider]['provider']}",
            data=spf_guides[provider]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving SPF guide: {str(e)}")


@router.get("/{provider}/dmarc", response_model=SuccessResponse)
async def get_provider_dmarc_guide(
    provider: str = Path(..., description="DNS provider slug", example="cloudflare")
):
    """
    Get DMARC-specific setup guide for a DNS provider.
    
    Returns detailed instructions for configuring DMARC records
    with provider-specific steps and best practices.
    """
    try:
        dmarc_guides = {
            "cloudflare": {
                "provider": "Cloudflare",
                "steps": [
                    "Log into your Cloudflare dashboard",
                    "Select your domain",
                    "Go to DNS settings",
                    "Add a new TXT record",
                    "Set name to _dmarc",
                    "Set value to your DMARC record",
                    "Set TTL to Auto",
                    "Save the record"
                ],
                "tips": [
                    "Start with p=none to monitor without affecting delivery",
                    "Set up report URIs to receive DMARC reports",
                    "Gradually increase policy strictness based on monitoring"
                ]
            },
            "godaddy": {
                "provider": "GoDaddy",
                "steps": [
                    "Log into your GoDaddy account",
                    "Go to My Products > DNS",
                    "Click Manage DNS",
                    "Add a new TXT record",
                    "Set Host to _dmarc",
                    "Set Value to your DMARC record",
                    "Set TTL to 1 Hour",
                    "Save the record"
                ],
                "tips": [
                    "Use monitoring policy initially",
                    "Set up email addresses for reports",
                    "Monitor reports before changing policy"
                ]
            },
            "route53": {
                "provider": "AWS Route53",
                "steps": [
                    "Go to AWS Route53 console",
                    "Select your hosted zone",
                    "Click Create Record",
                    "Select TXT record type",
                    "Set Record name to _dmarc",
                    "Set Value to your DMARC record",
                    "Set TTL to 300",
                    "Create the record"
                ],
                "tips": [
                    "Use AWS SNS for report notifications",
                    "Set up CloudWatch for monitoring",
                    "Consider using AWS SES for email reports"
                ]
            }
        }
        
        if provider not in dmarc_guides:
            raise HTTPException(status_code=404, detail=f"DMARC guide not found for provider: {provider}")
        
        return SuccessResponse(
            message=f"DMARC setup guide retrieved successfully for {dmarc_guides[provider]['provider']}",
            data=dmarc_guides[provider]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving DMARC guide: {str(e)}") 