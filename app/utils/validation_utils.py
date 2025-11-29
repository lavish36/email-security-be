import re
import ipaddress
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


class DomainValidator:
    """Domain name validation utilities."""
    
    # Domain name regex pattern
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    # IP address patterns
    IPV4_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    IPV6_PATTERN = re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain:
            return False
        
        # Remove protocol and www if present
        domain = domain.lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        
        # Check if it's a valid domain
        return bool(DomainValidator.DOMAIN_PATTERN.match(domain))
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """
        Normalize domain name.
        
        Args:
            domain: Domain name to normalize
            
        Returns:
            Normalized domain name
        """
        if not domain:
            return ""
        
        # Convert to lowercase
        domain = domain.lower()
        
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        
        # Remove www prefix
        domain = re.sub(r'^www\.', '', domain)
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        return domain
    
    @staticmethod
    def extract_domain_from_url(url: str) -> Optional[str]:
        """
        Extract domain from URL.
        
        Args:
            url: URL to extract domain from
            
        Returns:
            Domain name or None if invalid
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if not domain:
                return None
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            return DomainValidator.normalize_domain(domain)
        except Exception:
            return None
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Validate IP address.
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP address is private.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if private, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False


class SPFValidator:
    """SPF record validation utilities."""
    
    @staticmethod
    def validate_spf_mechanism(mechanism: str) -> Dict[str, Any]:
        """
        Validate SPF mechanism.
        
        Args:
            mechanism: SPF mechanism to validate
            
        Returns:
            Validation result
        """
        result = {
            'valid': False,
            'type': None,
            'value': None,
            'error': None
        }
        
        # Remove qualifier
        qualifier = ''
        if mechanism.startswith(('+', '-', '~', '?')):
            qualifier = mechanism[0]
            mechanism = mechanism[1:]
        
        # Validate mechanism types
        if mechanism == 'all':
            result['valid'] = True
            result['type'] = 'all'
        elif mechanism.startswith('include:'):
            domain = mechanism[8:]
            if DomainValidator.is_valid_domain(domain):
                result['valid'] = True
                result['type'] = 'include'
                result['value'] = domain
            else:
                result['error'] = f'Invalid domain in include: {domain}'
        elif mechanism.startswith('ip4:'):
            ip = mechanism[4:]
            if DomainValidator.is_valid_ip(ip) and ':' not in ip:
                result['valid'] = True
                result['type'] = 'ip4'
                result['value'] = ip
            else:
                result['error'] = f'Invalid IPv4 address: {ip}'
        elif mechanism.startswith('ip6:'):
            ip = mechanism[4:]
            if DomainValidator.is_valid_ip(ip) and ':' in ip:
                result['valid'] = True
                result['type'] = 'ip6'
                result['value'] = ip
            else:
                result['error'] = f'Invalid IPv6 address: {ip}'
        elif mechanism.startswith('a'):
            if mechanism == 'a':
                result['valid'] = True
                result['type'] = 'a'
                result['value'] = 'current'
            elif mechanism.startswith('a/'):
                # CIDR notation
                result['valid'] = True
                result['type'] = 'a'
                result['value'] = mechanism[2:]
            elif mechanism.startswith('a:'):
                domain = mechanism[2:]
                if DomainValidator.is_valid_domain(domain):
                    result['valid'] = True
                    result['type'] = 'a'
                    result['value'] = domain
                else:
                    result['error'] = f'Invalid domain in a: {domain}'
        elif mechanism.startswith('mx'):
            if mechanism == 'mx':
                result['valid'] = True
                result['type'] = 'mx'
                result['value'] = 'current'
            elif mechanism.startswith('mx/'):
                # CIDR notation
                result['valid'] = True
                result['type'] = 'mx'
                result['value'] = mechanism[3:]
            elif mechanism.startswith('mx:'):
                domain = mechanism[3:]
                if DomainValidator.is_valid_domain(domain):
                    result['valid'] = True
                    result['type'] = 'mx'
                    result['value'] = domain
                else:
                    result['error'] = f'Invalid domain in mx: {domain}'
        elif mechanism.startswith('exists:'):
            domain = mechanism[7:]
            if DomainValidator.is_valid_domain(domain):
                result['valid'] = True
                result['type'] = 'exists'
                result['value'] = domain
            else:
                result['error'] = f'Invalid domain in exists: {domain}'
        elif mechanism.startswith('ptr'):
            if mechanism == 'ptr':
                result['valid'] = True
                result['type'] = 'ptr'
                result['value'] = 'current'
            elif mechanism.startswith('ptr:'):
                domain = mechanism[4:]
                if DomainValidator.is_valid_domain(domain):
                    result['valid'] = True
                    result['type'] = 'ptr'
                    result['value'] = domain
                else:
                    result['error'] = f'Invalid domain in ptr: {domain}'
        else:
            result['error'] = f'Unknown SPF mechanism: {mechanism}'
        
        return result


class DKIMValidator:
    """DKIM record validation utilities."""
    
    @staticmethod
    def validate_selector(selector: str) -> bool:
        """
        Validate DKIM selector.
        
        Args:
            selector: DKIM selector to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not selector:
            return False
        
        # Selector should be alphanumeric and hyphens only
        return bool(re.match(r'^[a-zA-Z0-9-]+$', selector))
    
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
            'error': None
        }
        
        try:
            import base64
            # Try to decode base64
            key_bytes = base64.b64decode(public_key)
            
            # Basic validation - key should be reasonable size
            if len(key_bytes) < 100:
                result['error'] = 'Public key too short'
                return result
            
            if len(key_bytes) > 10000:
                result['error'] = 'Public key too long'
                return result
            
            result['valid'] = True
            result['key_size'] = len(key_bytes) * 8  # Approximate bit size
            
        except Exception as e:
            result['error'] = f'Invalid base64 encoding: {str(e)}'
        
        return result


class DMARCValidator:
    """DMARC record validation utilities."""
    
    @staticmethod
    def validate_policy(policy: str) -> bool:
        """
        Validate DMARC policy.
        
        Args:
            policy: DMARC policy to validate
            
        Returns:
            True if valid, False otherwise
        """
        valid_policies = ['none', 'quarantine', 'reject']
        return policy.lower() in valid_policies
    
    @staticmethod
    def validate_alignment_mode(mode: str) -> bool:
        """
        Validate DMARC alignment mode.
        
        Args:
            mode: Alignment mode to validate
            
        Returns:
            True if valid, False otherwise
        """
        return mode.lower() in ['r', 's']
    
    @staticmethod
    def validate_percentage(percentage: int) -> bool:
        """
        Validate DMARC percentage.
        
        Args:
            percentage: Percentage to validate
            
        Returns:
            True if valid, False otherwise
        """
        return 0 <= percentage <= 100
    
    @staticmethod
    def validate_report_uri(uri: str) -> bool:
        """
        Validate DMARC report URI.
        
        Args:
            uri: Report URI to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not uri:
            return False
        
        # Check if it's a mailto URI
        if uri.startswith('mailto:'):
            email = uri[7:]
            return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))
        
        # Check if it's an HTTP URI
        if uri.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(uri)
                return bool(parsed.netloc)
            except Exception:
                return False
        
        return False 