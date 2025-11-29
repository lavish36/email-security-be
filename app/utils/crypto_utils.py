import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Dict, Any
import secrets
import string
from datetime import datetime, timezone
import ssl
import socket


class DKIMKeyGenerator:
    """DKIM key pair generator."""
    
    @staticmethod
    def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[str, str]:
        """
        Generate RSA key pair for DKIM.
        
        Args:
            key_size: RSA key size in bits (1024, 2048, 4096)
            
        Returns:
            Tuple of (private_key_pem, public_key_dns)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Serialize public key to DNS format
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Encode to base64 for DNS
        public_key_dns = base64.b64encode(public_key_bytes).decode('utf-8')
        
        return private_key_pem, public_key_dns
    
    @staticmethod
    def generate_selector() -> str:
        """Generate a random DKIM selector."""
        # Generate a random selector with letters and numbers
        chars = string.ascii_lowercase + string.digits
        return ''.join(secrets.choice(chars) for _ in range(16))
    
    @staticmethod
    def create_dkim_dns_record(selector: str, public_key: str, algorithm: str = "rsa-sha256") -> str:
        """
        Create DKIM DNS TXT record.
        
        Args:
            selector: DKIM selector
            public_key: Base64 encoded public key
            algorithm: Signing algorithm
            
        Returns:
            DKIM DNS TXT record
        """
        return f'v=DKIM1; k=rsa; p={public_key}'
    
    @staticmethod
    def validate_public_key(public_key: str) -> Dict[str, Any]:
        """
        Validate DKIM public key.
        
        Args:
            public_key: Base64 encoded public key
            
        Returns:
            Validation result
        """
        result = {
            'valid': False,
            'key_size': None,
            'algorithm': None,
            'error': None
        }
        
        try:
            # Decode base64
            key_bytes = base64.b64decode(public_key)
            
            # Load public key
            public_key_obj = serialization.load_der_public_key(
                key_bytes,
                backend=default_backend()
            )
            
            # Get key size
            if hasattr(public_key_obj, 'key_size'):
                result['key_size'] = public_key_obj.key_size
            
            # Determine algorithm
            result['algorithm'] = 'rsa-sha256'
            result['valid'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        return result


class SPFGenerator:
    """SPF record generator."""
    
    # Common email provider SPF includes
    # Organized by category for better maintenance
    PROVIDER_INCLUDES = {
        # Major Email Platforms
        'google': '_spf.google.com',
        'gmail': '_spf.google.com',
        'google_workspace': '_spf.google.com',
        'outlook': '_spf.protection.outlook.com',
        'office365': '_spf.protection.outlook.com',
        'microsoft365': '_spf.protection.outlook.com',
        'microsoft365_gcc': 'spf-a.outlook.com',  # Government Cloud
        'zoho': 'zoho.com',
        'zoho_mail': 'zoho.com',
        'yahoo': 'yahoo.com',
        'protonmail': '_spf.protonmail.ch',
        'fastmail': 'spf.messagingengine.com',
        'icloud': 'icloud.com',
        'aol': 'aol.com',
        'rackspace': 'emailsrvr.com',
        'godaddy': 'secureserver.net',
        
        # Transactional Email Services
        'sendgrid': '_spf.sendgrid.net',
        'mailgun': '_spf.mailgun.org',
        'amazonses': 'amazonses.com',
        'amazon_ses': 'amazonses.com',
        'postmark': 'spf.mtasv.net',
        'sparkpost': '_spf.sparkpostmail.com',
        'mandrill': 'spf.mandrillapp.com',
        'sendinblue': 'spf.sendinblue.com',
        'brevo': 'spf.sendinblue.com',  # Sendinblue rebranded to Brevo
        'elastic_email': 'elasticemail.com',
        'socketlabs': '_spf.socketlabs.com',
        
        # Marketing & Email Campaign Platforms
        'mailchimp': '_spf.mailchimp.com',
        'constant_contact': '_spf.constantcontact.com',
        'hubspot': '_spf.hubspot.com',
        'salesforce': '_spf.salesforce.com',
        'pardot': '_spf.salesforce.com',
        'klaviyo': '_spf.klaviyo.com',
        'convertkit': '_spf.convertkit.com',
        'activecampaign': '_spf.activecampaign.com',
        'drip': '_spf.drip.com',
        'getresponse': '_spf.getresponse.com',
        'aweber': '_spf.aweber.com',
        'campaign_monitor': 'cmail1.com',
        'omnisend': '_spf.omnisend.com',
        'mailerlite': '_spf.mailerlite.com',
        'sendy': 'amazonses.com',  # Sendy typically uses SES
        'moosend': '_spf.moosend.com',
        
        # Customer Support & CRM
        'zendesk': '_spf.zendesk.com',
        'intercom': '_spf.intercom.io',
        'freshdesk': '_spf.freshdesk.com',
        'helpscout': '_spf.helpscout.net',
        'drift': '_spf.drift.com',
        
        # Legacy Marketing Automation
        'infusionsoft': '_spf.infusionsoft.com',
        'keap': '_spf.infusionsoft.com',  # Infusionsoft rebranded to Keap
        'ontraport': '_spf.ontraport.com',
        'autopilot': '_spf.autopilothq.com',
        
        # E-commerce & Business Platforms
        'shopify': 'shops.shopify.com',
        'stripe': '_spf.stripe.com',
        'square': '_spf.squareup.com',
        'paypal': '_spf.paypal.com',
        'quickbooks': 'notification.intuit.com',
    }
    
    @staticmethod
    def generate_spf_record(
        providers: list = None,
        include_all: bool = False,
        custom_mechanisms: list = None
    ) -> str:
        """
        Generate SPF record.
        
        Args:
            providers: List of email providers to include
            include_all: Include all common providers
            custom_mechanisms: Custom SPF mechanisms
            
        Returns:
            Generated SPF record
        """
        mechanisms = ['v=spf1']
        
        # Add provider includes
        if include_all:
            for provider, include in SPFGenerator.PROVIDER_INCLUDES.items():
                mechanisms.append(f'include:{include}')
        elif providers:
            for provider in providers:
                if provider.lower() in SPFGenerator.PROVIDER_INCLUDES:
                    mechanisms.append(f'include:{SPFGenerator.PROVIDER_INCLUDES[provider.lower()]}')
        
        # Add custom mechanisms
        if custom_mechanisms:
            mechanisms.extend(custom_mechanisms)
        
        return ' '.join(mechanisms)
    
    @staticmethod
    def get_available_providers() -> Dict[str, Any]:
        """Get list of available email providers with metadata and categories."""
        # Provider categories for better organization
        categories = {
            'email': {
                'name': 'Email Platforms',
                'providers': ['google', 'gmail', 'google_workspace', 'outlook', 'office365', 
                             'microsoft365', 'microsoft365_gcc', 'zoho', 'zoho_mail', 'yahoo', 
                             'protonmail', 'fastmail', 'icloud', 'aol', 'rackspace', 'godaddy']
            },
            'transactional': {
                'name': 'Transactional Email Services',
                'providers': ['sendgrid', 'mailgun', 'amazonses', 'amazon_ses', 'postmark', 
                             'sparkpost', 'mandrill', 'sendinblue', 'brevo', 'elastic_email', 
                             'socketlabs']
            },
            'marketing': {
                'name': 'Marketing & Campaigns',
                'providers': ['mailchimp', 'constant_contact', 'hubspot', 'klaviyo', 
                             'convertkit', 'activecampaign', 'drip', 'getresponse', 'aweber', 
                             'campaign_monitor', 'omnisend', 'mailerlite', 'sendy', 'moosend']
            },
            'crm': {
                'name': 'CRM & Support',
                'providers': ['salesforce', 'pardot', 'zendesk', 'intercom', 'freshdesk', 
                             'helpscout', 'drift', 'infusionsoft', 'keap', 'ontraport', 
                             'autopilot']
            },
            'ecommerce': {
                'name': 'E-commerce & Business',
                'providers': ['shopify', 'stripe', 'square', 'paypal', 'quickbooks']
            }
        }
        
        # Popular providers (most commonly used)
        popular = ['google', 'outlook', 'sendgrid', 'mailgun', 'mailchimp', 
                  'amazonses', 'hubspot', 'zoho']
        
        # Build provider data with metadata
        providers_data = {}
        for key, include in SPFGenerator.PROVIDER_INCLUDES.items():
            providers_data[key] = {
                'include': include,
                'popular': key in popular,
                'category': next((cat for cat, data in categories.items() 
                                if key in data['providers']), 'other')
            }
        
        return {
            'providers': providers_data,
            'categories': categories,
            'popular': popular,
            'total': len(SPFGenerator.PROVIDER_INCLUDES)
        }
    
    @staticmethod
    def get_providers_simple() -> Dict[str, str]:
        """Get simple key-value list of providers (backward compatibility)."""
        return SPFGenerator.PROVIDER_INCLUDES.copy()


class SPFOptimizer:
    """SPF record optimizer and analyzer."""
    
    @staticmethod
    def analyze_spf_record(record: str) -> Dict[str, Any]:
        """
        Analyze SPF record for potential issues.
        
        Args:
            record: SPF record to analyze
            
        Returns:
            Analysis result with warnings and recommendations
        """
        result = {
            'valid': False,
            'lookup_count': 0,
            'mechanisms': [],
            'warnings': [],
            'errors': [],
            'recommendations': [],
            'record_length': len(record),
            'max_length': 255
        }
        
        try:
            # Check if valid SPF record
            if not record.startswith('v=spf1'):
                result['errors'].append('SPF record must start with "v=spf1"')
                return result
            
            # Parse mechanisms
            parts = record.split()
            result['mechanisms'] = parts[1:]  # Skip v=spf1
            
            # Count DNS lookups
            lookup_mechanisms = ['include', 'a', 'mx', 'exists', 'redirect']
            for part in result['mechanisms']:
                mechanism_type = part.split(':')[0].replace('+', '').replace('-', '').replace('~', '').replace('?', '')
                if mechanism_type in lookup_mechanisms:
                    result['lookup_count'] += 1
            
            # Check lookup limit
            if result['lookup_count'] > 10:
                result['errors'].append(f'SPF record exceeds DNS lookup limit (10): {result["lookup_count"]} lookups')
                result['recommendations'].append('Consider flattening SPF includes to reduce lookups')
            elif result['lookup_count'] > 8:
                result['warnings'].append(f'SPF record approaching DNS lookup limit: {result["lookup_count"]}/10')
                result['recommendations'].append('Monitor SPF includes to avoid exceeding limit')
            
            # Check record length
            if result['record_length'] > 255:
                result['errors'].append(f'SPF record exceeds 255 characters: {result["record_length"]}')
                result['recommendations'].append('Split SPF record into multiple TXT strings')
            elif result['record_length'] > 200:
                result['warnings'].append(f'SPF record approaching character limit: {result["record_length"]}/255')
            
            # Check for all mechanism
            all_mechanisms = [p for p in result['mechanisms'] if p in ['~all', '-all', '+all', '?all']]
            if not all_mechanisms:
                result['warnings'].append('No "all" mechanism found - consider adding ~all or -all')
                result['recommendations'].append('Add "~all" for soft fail or "-all" for hard fail')
            elif len(all_mechanisms) > 1:
                result['errors'].append('Multiple "all" mechanisms found')
            elif all_mechanisms[0] != result['mechanisms'][-1]:
                result['warnings'].append('"all" mechanism should be the last mechanism')
            
            # Check for duplicate includes
            includes = [p.split(':')[1] for p in result['mechanisms'] if p.startswith('include:')]
            if len(includes) != len(set(includes)):
                duplicates = [inc for inc in includes if includes.count(inc) > 1]
                result['warnings'].append(f'Duplicate includes found: {", ".join(set(duplicates))}')
                result['recommendations'].append('Remove duplicate include mechanisms')
            
            # Check for ip4/ip6 without CIDR
            for part in result['mechanisms']:
                if part.startswith('ip4:') and '/' not in part:
                    result['recommendations'].append(f'Consider specifying CIDR for {part}')
                if part.startswith('ip6:') and '/' not in part:
                    result['recommendations'].append(f'Consider specifying CIDR for {part}')
            
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f'Error analyzing SPF record: {str(e)}')
        
        return result
    
    @staticmethod
    def get_optimization_suggestions(record: str) -> Dict[str, Any]:
        """
        Get optimization suggestions for an SPF record.
        
        Args:
            record: SPF record to optimize
            
        Returns:
            Optimization suggestions
        """
        analysis = SPFOptimizer.analyze_spf_record(record)
        
        suggestions = {
            'current_record': record,
            'analysis': analysis,
            'optimizations': [],
            'estimated_improvement': {}
        }
        
        # Suggest removing duplicates
        mechanisms = record.split()[1:]
        unique_mechanisms = []
        seen = set()
        for mech in mechanisms:
            if mech not in seen:
                unique_mechanisms.append(mech)
                seen.add(mech)
        
        if len(unique_mechanisms) < len(mechanisms):
            optimized = f'v=spf1 {" ".join(unique_mechanisms)}'
            suggestions['optimizations'].append({
                'type': 'remove_duplicates',
                'description': 'Remove duplicate mechanisms',
                'optimized_record': optimized
            })
        
        # Suggest moving 'all' to end
        all_mech = None
        other_mechs = []
        for mech in unique_mechanisms:
            if mech in ['~all', '-all', '+all', '?all']:
                all_mech = mech
            else:
                other_mechs.append(mech)
        
        if all_mech and unique_mechanisms[-1] != all_mech:
            optimized = f'v=spf1 {" ".join(other_mechs)} {all_mech}'
            suggestions['optimizations'].append({
                'type': 'reorder_all',
                'description': 'Move "all" mechanism to end',
                'optimized_record': optimized
            })
        
        # Estimate improvement
        suggestions['estimated_improvement'] = {
            'lookup_reduction': 0,  # Would need DNS resolution to calculate
            'length_reduction': max(0, len(record) - len(suggestions['optimizations'][-1]['optimized_record']) if suggestions['optimizations'] else 0)
        }
        
        return suggestions


class DMARCGenerator:
    """DMARC record generator."""
    
    @staticmethod
    def generate_dmarc_record(
        policy: str = "none",
        subdomain_policy: str = "none",
        percentage: int = 100,
        report_uri: str = None,
        forensic_uri: str = None,
        adkim: str = "r",
        aspf: str = "r"
    ) -> str:
        """
        Generate DMARC record.
        
        Args:
            policy: DMARC policy (none, quarantine, reject)
            subdomain_policy: Subdomain policy
            percentage: Percentage of messages to filter
            report_uri: URI for aggregate reports
            forensic_uri: URI for forensic reports
            adkim: DKIM alignment mode
            aspf: SPF alignment mode
            
        Returns:
            Generated DMARC record
        """
        parts = ['v=DMARC1']
        
        # Add policy
        parts.append(f'p={policy}')
        
        # Add subdomain policy
        parts.append(f'sp={subdomain_policy}')
        
        # Add percentage
        if percentage != 100:
            parts.append(f'pct={percentage}')
        
        # Add alignment modes
        parts.append(f'adkim={adkim}')
        parts.append(f'aspf={aspf}')
        
        # Add report URIs
        if report_uri:
            rua_value = report_uri if report_uri.startswith('mailto:') else f'mailto:{report_uri}'
            parts.append(f'rua={rua_value}')
        
        if forensic_uri:
            ruf_value = forensic_uri if forensic_uri.startswith('mailto:') else f'mailto:{forensic_uri}'
            parts.append(f'ruf={ruf_value}')
        
        return '; '.join(parts)
    
    @staticmethod
    def get_policy_recommendations() -> Dict[str, Dict[str, str]]:
        """Get DMARC policy recommendations."""
        return {
            'none': {
                'description': 'Monitor only - no action taken',
                'recommendation': 'Use for initial setup and testing',
                'risk': 'low'
            },
            'quarantine': {
                'description': 'Quarantine suspicious emails',
                'recommendation': 'Use after monitoring phase',
                'risk': 'medium'
            },
            'reject': {
                'description': 'Reject suspicious emails',
                'recommendation': 'Use only after thorough testing',
                'risk': 'high'
            }
        }


class MTASTSGenerator:
    """MTA-STS record and policy generator."""
    
    @staticmethod
    def generate_mtasts_record(domain: str) -> str:
        """
        Generate MTA-STS DNS TXT record.
        
        Args:
            domain: Domain name
            
        Returns:
            MTA-STS DNS TXT record
        """
        # Use a dynamic policy id so updates propagate quickly across caches
        id_value = str(int(datetime.now(timezone.utc).timestamp()))
        return f'v=STSv1; id={id_value}'
    
    @staticmethod
    def generate_mtasts_policy(
        mode: str = "testing",
        max_age: int = 86400,
        mx_records: list = None,
        include_subdomains: bool = False
    ) -> str:
        """
        Generate MTA-STS policy file content.
        
        Args:
            mode: MTA-STS mode (testing, enforce, none)
            max_age: Policy max age in seconds
            mx_records: List of MX records
            include_subdomains: Include subdomains
            
        Returns:
            MTA-STS policy content
        """
        if mx_records is None:
            mx_records = []
        
        # Normalize and clamp inputs
        valid_modes = ['testing', 'enforce', 'none']
        normalized_mode = mode if mode in valid_modes else 'testing'
        clamped_max_age = max(300, min(int(max_age), 31536000))

        policy_lines = [
            'version: STSv1',
            f'mode: {normalized_mode}',
            f'max_age: {clamped_max_age}'
        ]
        
        if mx_records:
            # Deduplicate and normalize MX entries
            seen = set()
            normalized_mx = []
            for mx in mx_records:
                entry = str(mx).strip()
                if entry and entry not in seen:
                    seen.add(entry)
                    normalized_mx.append(entry)
            if normalized_mx:
                policy_lines.append('mx:')
                for mx in normalized_mx:
                    policy_lines.append(f'  - {mx}')
        
        if include_subdomains:
            policy_lines.append('subdomains: true')
        
        return '\n'.join(policy_lines)
    
    @staticmethod
    def validate_mtasts_policy(policy_content: str) -> Dict[str, Any]:
        """
        Validate MTA-STS policy content.
        
        Args:
            policy_content: MTA-STS policy content
            
        Returns:
            Validation result
        """
        result = {
            'valid': False,
            'version': None,
            'mode': None,
            'max_age': None,
            'mx_records': [],
            'include_subdomains': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            lines = policy_content.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'version':
                        result['version'] = value
                        if value != 'STSv1':
                            result['errors'].append('Invalid version - must be STSv1')
                    elif key == 'mode':
                        result['mode'] = value
                        if value not in ['testing', 'enforce', 'none']:
                            result['errors'].append('Invalid mode - must be testing, enforce, or none')
                    elif key == 'max_age':
                        try:
                            result['max_age'] = int(value)
                            if result['max_age'] < 300 or result['max_age'] > 31536000:
                                result['warnings'].append('Max age should be between 300 and 31536000 seconds')
                        except ValueError:
                            result['errors'].append('Invalid max_age - must be a number')
                    elif key == 'mx':
                        # MX records are handled separately
                        continue
                    elif key == 'subdomains':
                        result['include_subdomains'] = value.lower() == 'true'
            
            # Validate required fields
            if not result['version']:
                result['errors'].append('Missing version field')
            if not result['mode']:
                result['errors'].append('Missing mode field')
            if not result['max_age']:
                result['errors'].append('Missing max_age field')
            
            # Check if valid
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f'Error parsing policy: {str(e)}')
        
        return result


class TLSRPTGenerator:
    """TLS-RPT record generator."""
    
    @staticmethod
    def generate_tlsrpt_record(
        domain: str,
        report_uri: str = "mailto:tls-reports@example.com",
        include_subdomains: bool = False
    ) -> str:
        """
        Generate TLS-RPT DNS TXT record.
        
        Args:
            domain: Domain name
            report_uri: URI for TLS reports
            include_subdomains: Include subdomains
            
        Returns:
            TLS-RPT DNS TXT record
        """
        # Support multiple URIs via comma-separated list and normalize prefixes
        uri_candidates = [u.strip() for u in report_uri.split(',')] if report_uri else []
        normalized_uris = []
        seen = set()
        for uri in uri_candidates:
            if not uri:
                continue
            if uri.startswith('mailto:') or uri.startswith('https:'):
                normalized = uri
            else:
                # If it looks like an email, prefix with mailto:
                normalized = f'mailto:{uri}'
            if normalized not in seen:
                seen.add(normalized)
                normalized_uris.append(normalized)
        # Fallback to default if none provided after normalization
        if not normalized_uris:
            normalized_uris = [report_uri if report_uri else 'mailto:tls-reports@example.com']
        record = f"v=TLSRPTv1; rua={','.join(normalized_uris)}"
        
        if include_subdomains:
            record += '; subdomains=true'
        
        return record
    
    @staticmethod
    def validate_tlsrpt_record(record: str) -> Dict[str, Any]:
        """
        Validate TLS-RPT record.
        
        Args:
            record: TLS-RPT record
            
        Returns:
            Validation result
        """
        result = {
            'valid': False,
            'version': None,
            'rua': None,
            'include_subdomains': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'v':
                        result['version'] = value
                        if value != 'TLSRPTv1':
                            result['errors'].append('Invalid version - must be TLSRPTv1')
                    elif key == 'rua':
                        result['rua'] = value
                        if not value.startswith('mailto:'):
                            result['warnings'].append('Report URI should start with mailto:')
                    elif key == 'subdomains':
                        result['include_subdomains'] = value.lower() == 'true'
            
            # Validate required fields
            if not result['version']:
                result['errors'].append('Missing version field')
            if not result['rua']:
                result['errors'].append('Missing rua field')
            
            # Check if valid
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f'Error parsing record: {str(e)}')
        
        return result 


def validate_certificate(cert: Dict[str, Any]) -> bool:
    """
    Validate SSL certificate.
    
    Args:
        cert: Certificate dictionary from ssl.getpeercert()
        
    Returns:
        True if certificate is valid, False otherwise
    """
    try:
        # Check if certificate has required fields
        if not cert or 'notBefore' not in cert or 'notAfter' not in cert:
            return False
        
        # Parse dates
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        # Get current time
        now = datetime.now(timezone.utc)
        
        # Check if certificate is currently valid
        if now < not_before or now > not_after:
            return False
        
        # Check if certificate has subject and issuer
        if 'subject' not in cert or 'issuer' not in cert:
            return False
        
        return True
        
    except Exception:
        return False


def check_certificate_expiry(cert: Dict[str, Any]) -> int:
    """
    Calculate days until certificate expiry.
    
    Args:
        cert: Certificate dictionary from ssl.getpeercert()
        
    Returns:
        Days until expiry (negative if expired)
    """
    try:
        if not cert or 'notAfter' not in cert:
            return -1
        
        # Parse expiry date
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        # Get current time
        now = datetime.now(timezone.utc)
        
        # Calculate difference
        delta = not_after - now
        return delta.days
        
    except Exception:
        return -1


def get_certificate_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Get detailed certificate information for a host.
    
    Args:
        hostname: Hostname to check
        port: Port to connect to
        
    Returns:
        Certificate information dictionary
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'serial_number': cert['serialNumber'],
                    'version': cert['version'],
                    'san': cert.get('subjectAltName', []),
                    'is_valid': validate_certificate(cert),
                    'days_until_expiry': check_certificate_expiry(cert),
                    'tls_version': ssock.version(),
                    'cipher': ssock.cipher()
                }
                
    except Exception as e:
        return {
            'error': str(e),
            'is_valid': False,
            'days_until_expiry': -1
        } 