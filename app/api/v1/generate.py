from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from app.models.domain import (
    SPFGeneratorRequest, DKIMGeneratorRequest, DMARCGeneratorRequest,
    MTASTSGeneratorRequest, TLSRPTGeneratorRequest
)
from app.models.responses import SuccessResponse
from app.models.security import GeneratedRecord


router = APIRouter(prefix="/api/v1/generate", tags=["Record Generation"])


@router.post("/spf", response_model=SuccessResponse)
async def generate_spf_record(request: SPFGeneratorRequest):
    """
    Generate SPF (Sender Policy Framework) record.
    
    Creates a properly formatted SPF record based on your email providers
    and custom requirements with validation and export options.
    """
    try:
        # Import here to avoid circular import
        from app.utils.crypto_utils import SPFGenerator, SPFOptimizer
        
        # Generate SPF record
        spf_record = SPFGenerator.generate_spf_record(
            providers=request.email_providers,
            include_all=request.include_all,
            custom_mechanisms=request.custom_mechanisms
        )
        
        # Analyze the generated SPF record
        analysis = SPFOptimizer.analyze_spf_record(spf_record)
        
        # Create instructions
        instructions = [
            f"Add this TXT record to your DNS for domain: {request.domain}",
            "Record Type: TXT",
            f"Name: {request.domain} (or @ for root domain)",
            f"Value: {spf_record}",
            "TTL: 3600 (or your preferred TTL)"
        ]
        
        # Add provider-specific instructions
        if request.email_providers:
            instructions.append("")
            instructions.append("Email providers included:")
            for provider in request.email_providers:
                if provider.lower() in SPFGenerator.PROVIDER_INCLUDES:
                    instructions.append(f"- {provider}: {SPFGenerator.PROVIDER_INCLUDES[provider.lower()]}")
        
        # Add warnings from analysis
        warnings = analysis.get('warnings', [])
        if len(request.email_providers) > 10:
            warnings.append("Many email providers may cause DNS lookup issues")
        
        if request.include_all and len(SPFGenerator.PROVIDER_INCLUDES) > 10:
            warnings.append("Including all providers may exceed DNS lookup limits")
        
        # Add analysis errors as warnings
        warnings.extend(analysis.get('errors', []))
        
        # Validation metadata
        validation = {
            'syntax_valid': analysis.get('valid', False),
            'dns_lookup_count': f"{analysis.get('lookup_count', 0)}/10",
            'record_length': f"{analysis.get('record_length', 0)}/{analysis.get('max_length', 255)}",
            'estimated_propagation_time': '1-4 hours',
            'common_issues': analysis.get('recommendations', [])
        }
        
        # Export formats
        export_formats = {
            'bind': f'{request.domain}. IN TXT "{spf_record}"',
            'json': f'{{"name": "{request.domain}", "type": "TXT", "value": "{spf_record}", "ttl": 3600}}',
            'cloudflare': f'{{"type": "TXT", "name": "{request.domain}", "content": "{spf_record}", "ttl": 3600}}'
        }
        
        # Related records suggestions
        related_records = [
            {
                'type': 'dkim',
                'suggestion': 'Generate DKIM record for email authentication',
                'priority': 'high'
            },
            {
                'type': 'dmarc',
                'suggestion': 'Add DMARC policy for email security',
                'priority': 'high'
            }
        ]
        
        # Popular DNS provider guides
        provider_guides = [
            {
                'provider': 'cloudflare',
                'quick_steps': [
                    'Log in to Cloudflare dashboard',
                    'Select your domain',
                    'Go to DNS settings',
                    'Add TXT record with name @ and value from above'
                ]
            },
            {
                'provider': 'route53',
                'quick_steps': [
                    'Open AWS Route 53 console',
                    'Select hosted zone',
                    'Create Record Set',
                    'Type: TXT, Name: your domain, Value: SPF record'
                ]
            },
            {
                'provider': 'godaddy',
                'quick_steps': [
                    'Log in to GoDaddy',
                    'My Products > DNS',
                    'Add > TXT record',
                    'Host: @, TXT Value: SPF record'
                ]
            }
        ]
        
        return SuccessResponse(
            success=True,
            message="SPF record generated successfully",
            data=GeneratedRecord(
                record_type="TXT",
                name=request.domain,
                value=spf_record,
                ttl=3600,
                instructions=instructions,
                warnings=warnings,
                validation=validation,
                export_formats=export_formats,
                related_records=related_records,
                provider_guides=provider_guides,
                estimated_propagation_time="1-4 hours"
            )
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating SPF record: {str(e)}")


@router.post("/dkim", response_model=SuccessResponse)
async def generate_dkim_record(request: DKIMGeneratorRequest):
    """
    Generate DKIM (DomainKeys Identified Mail) key pair and DNS record.
    
    Creates a new RSA key pair and generates the corresponding DKIM DNS record.
    """
    try:
        from app.utils.crypto_utils import DKIMKeyGenerator
        
        # Generate key pair
        private_key, public_key = DKIMKeyGenerator.generate_rsa_key_pair(request.key_size)
        
        # Generate selector if not provided
        selector = request.selector if request.selector != "default" else DKIMKeyGenerator.generate_selector()
        
        # Create DKIM DNS record
        dkim_record = DKIMKeyGenerator.create_dkim_dns_record(selector, public_key, request.algorithm)
        
        # Create instructions
        instructions = [
            f"Add this TXT record to your DNS for domain: {request.domain}",
            "Record Type: TXT",
            f"Name: {selector}._domainkey.{request.domain}",
            f"Value: {dkim_record}",
            "TTL: 3600 (or your preferred TTL)",
            "",
            "IMPORTANT: Keep your private key secure and configure your email server to use it for signing."
        ]
        
        # Add key information
        instructions.extend([
            "",
            "Key Information:",
            f"- Algorithm: {request.algorithm}",
            f"- Key Size: {request.key_size} bits",
            f"- Selector: {selector}",
            "",
            "Private Key (keep secure):",
            private_key
        ])
        
        return SuccessResponse(
            success=True,
            message="DKIM key pair and record generated successfully",
            data=GeneratedRecord(
                record_type="TXT",
                name=f"{selector}._domainkey.{request.domain}",
                value=dkim_record,
                ttl=3600,
                instructions=instructions,
                warnings=["Store the private key securely and configure your email server"]
            )
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating DKIM record: {str(e)}")


@router.post("/dmarc", response_model=SuccessResponse)
async def generate_dmarc_record(request: DMARCGeneratorRequest):
    """
    Generate DMARC (Domain-based Message Authentication, Reporting & Conformance) record.
    
    Creates a properly formatted DMARC record with your specified policy and reporting settings.
    """
    try:
        from app.utils.crypto_utils import DMARCGenerator
        
        # Generate DMARC record
        dmarc_record = DMARCGenerator.generate_dmarc_record(
            policy=request.policy,
            subdomain_policy=request.subdomain_policy,
            percentage=request.percentage,
            report_uri=request.report_uri,
            forensic_uri=request.forensic_uri,
            adkim=request.adkim,
            aspf=request.aspf
        )
        
        # Create instructions
        instructions = [
            f"Add this TXT record to your DNS for domain: {request.domain}",
            "Record Type: TXT",
            f"Name: _dmarc.{request.domain}",
            f"Value: {dmarc_record}",
            "TTL: 3600 (or your preferred TTL)"
        ]
        
        # Add policy recommendations
        policy_info = DMARCGenerator.get_policy_recommendations()
        if request.policy in policy_info:
            info = policy_info[request.policy]
            instructions.extend([
                "",
                f"Policy Information:",
                f"- Policy: {request.policy}",
                f"- Description: {info['description']}",
                f"- Recommendation: {info['recommendation']}",
                f"- Risk Level: {info['risk']}"
            ])
        
        # Add warnings
        warnings = []
        if request.policy == "reject":
            warnings.append("Reject policy will block emails that fail authentication - test thoroughly first")
        
        if not request.report_uri:
            warnings.append("No report URI specified - you won't receive DMARC reports")
        
        return SuccessResponse(
            success=True,
            message="DMARC record generated successfully",
            data=GeneratedRecord(
                record_type="TXT",
                name=f"_dmarc.{request.domain}",
                value=dmarc_record,
                ttl=3600,
                instructions=instructions,
                warnings=warnings
            )
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating DMARC record: {str(e)}")


@router.post("/mtasts", response_model=SuccessResponse)
async def generate_mtasts_record(request: MTASTSGeneratorRequest):
    """
    Generate MTA-STS (Mail Transfer Agent Strict Transport Security) record and policy.
    
    Creates both the DNS TXT record and the policy file content for MTA-STS implementation.
    """
    try:
        from app.utils.crypto_utils import MTASTSGenerator
        
        # Generate MTA-STS DNS record
        mtasts_record = MTASTSGenerator.generate_mtasts_record(request.domain)
        
        # Generate MTA-STS policy
        mtasts_policy = MTASTSGenerator.generate_mtasts_policy(
            mode=request.mode,
            max_age=request.max_age,
            mx_records=request.mx_records,
            include_subdomains=request.include_subdomains
        )
        
        # Create instructions
        instructions = [
            f"Step 1: Add this TXT record to your DNS for domain: {request.domain}",
            "Record Type: TXT",
            f"Name: {request.domain} (or @ for root domain)",
            f"Value: {mtasts_record}",
            "TTL: 3600 (or your preferred TTL)",
            "",
            f"Step 2: Create MTA-STS policy file",
            f"URL: https://mta-sts.{request.domain}/.well-known/mta-sts.txt",
            "Content-Type: text/plain",
            "Content:",
            mtasts_policy,
            "",
            "Step 3: Ensure your web server serves the policy file correctly",
            "- File must be accessible via HTTPS",
            "- Content-Type should be text/plain",
            "- No redirects should be used"
        ]
        
        # Add mode-specific instructions
        if request.mode == "testing":
            instructions.extend([
                "",
                "Testing Mode:",
                "- Emails will still be delivered even if TLS fails",
                "- Monitor logs for TLS failures",
                "- Move to 'enforce' mode after testing"
            ])
        elif request.mode == "enforce":
            instructions.extend([
                "",
                "Enforce Mode:",
                "- Emails will be rejected if TLS fails",
                "- Ensure all mail servers support TLS",
                "- Monitor for delivery issues"
            ])
        
        # Add warnings
        warnings = []
        if request.mode == "enforce":
            warnings.append("Enforce mode will reject emails if TLS fails - ensure all servers support TLS")
        
        if not request.mx_records:
            warnings.append("No MX records specified in policy - consider adding your mail servers")
        
        if request.max_age < 86400:
            warnings.append("Short max_age may cause frequent policy fetches")
        
        return SuccessResponse(
            success=True,
            message="MTA-STS record and policy generated successfully",
            data=GeneratedRecord(
                record_type="TXT",
                name=request.domain,
                value=mtasts_record,
                ttl=3600,
                instructions=instructions,
                warnings=warnings
            )
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating MTA-STS record: {str(e)}")


@router.post("/tlsrpt", response_model=SuccessResponse)
async def generate_tlsrpt_record(request: TLSRPTGeneratorRequest):
    """
    Generate TLS-RPT (TLS Reporting) record.
    
    Creates a properly formatted TLS-RPT record for receiving TLS failure reports.
    """
    try:
        from app.utils.crypto_utils import TLSRPTGenerator
        
        # Generate TLS-RPT record
        tlsrpt_record = TLSRPTGenerator.generate_tlsrpt_record(
            domain=request.domain,
            report_uri=request.report_uri,
            include_subdomains=request.include_subdomains
        )
        
        # Create instructions
        instructions = [
            f"Add this TXT record to your DNS for domain: {request.domain}",
            "Record Type: TXT",
            f"Name: _smtp._tls.{request.domain}",
            f"Value: {tlsrpt_record}",
            "TTL: 3600 (or your preferred TTL)",
            "",
            "TLS-RPT Information:",
            "- This record enables TLS failure reporting",
            "- Reports will be sent to the specified email address",
            "- Monitor reports to identify TLS issues",
            "- Use reports to improve TLS configuration"
        ]
        
        # Add subdomain information
        if request.include_subdomains:
            instructions.extend([
                "",
                "Subdomain Reporting:",
                "- TLS reports will include subdomain failures",
                "- Ensure subdomains are properly configured"
            ])
        
        # Add warnings
        warnings = []
        if not request.report_uri.startswith("mailto:"):
            warnings.append("Report URI should start with 'mailto:' for email reports")
        
        return SuccessResponse(
            success=True,
            message="TLS-RPT record generated successfully",
            data=GeneratedRecord(
                record_type="TXT",
                name=f"_smtp._tls.{request.domain}",
                value=tlsrpt_record,
                ttl=3600,
                instructions=instructions,
                warnings=warnings
            )
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating TLS-RPT record: {str(e)}")


@router.get("/spf/providers", response_model=SuccessResponse)
async def get_spf_providers():
    """
    Get list of available email providers for SPF record generation.
    
    Returns a dictionary of provider names with metadata, categories, and popularity indicators.
    """
    try:
        from app.utils.crypto_utils import SPFGenerator
        
        providers = SPFGenerator.get_available_providers()
        
        return SuccessResponse(
            success=True,
            message="Available SPF providers retrieved successfully",
            data=providers
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving SPF providers: {str(e)}")


@router.get("/dmarc/policies", response_model=SuccessResponse)
async def get_dmarc_policies():
    """
    Get DMARC policy recommendations and information.
    
    Returns detailed information about each DMARC policy type with recommendations.
    """
    try:
        from app.utils.crypto_utils import DMARCGenerator
        
        policies = DMARCGenerator.get_policy_recommendations()
        
        return SuccessResponse(
            success=True,
            message="DMARC policy information retrieved successfully",
            data=policies
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving DMARC policies: {str(e)}") 