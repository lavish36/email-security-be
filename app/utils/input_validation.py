"""
Comprehensive input validation utilities for the Domain Security API.
Handles edge cases and provides detailed error messages.
"""

import re
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse


class InputValidator:
    """Comprehensive input validation for API endpoints."""
    
    # Domain validation regex (RFC 1035)
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    # Maximum lengths
    MAX_DOMAIN_LENGTH = 253
    MAX_LABEL_LENGTH = 63
    MAX_IP_LENGTH = 45  # IPv6 max length
    
    @staticmethod
    def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
        """
        Validate domain name with comprehensive edge case handling.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check for None or empty
        if not domain:
            return False, "Domain cannot be empty"
        
        # Check type
        if not isinstance(domain, str):
            return False, "Domain must be a string"
        
        # Strip whitespace
        domain = domain.strip()
        
        # Check length
        if len(domain) > InputValidator.MAX_DOMAIN_LENGTH:
            return False, f"Domain exceeds maximum length of {InputValidator.MAX_DOMAIN_LENGTH} characters"
        
        if len(domain) < 1:
            return False, "Domain is too short"
        
        # Check for invalid characters at start/end
        if domain.startswith('.') or domain.endswith('.'):
            return False, "Domain cannot start or end with a dot"
        
        if domain.startswith('-') or domain.endswith('-'):
            return False, "Domain cannot start or end with a hyphen"
        
        # Check for consecutive dots
        if '..' in domain:
            return False, "Domain cannot contain consecutive dots"
        
        # Check each label
        labels = domain.split('.')
        for label in labels:
            if len(label) > InputValidator.MAX_LABEL_LENGTH:
                return False, f"Domain label '{label}' exceeds maximum length of {InputValidator.MAX_LABEL_LENGTH} characters"
            
            if len(label) == 0:
                return False, "Domain cannot have empty labels"
            
            # Check for invalid characters
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                return False, f"Domain label '{label}' contains invalid characters"
            
            # Labels cannot start or end with hyphen
            if label.startswith('-') or label.endswith('-'):
                return False, f"Domain label '{label}' cannot start or end with hyphen"
        
        # Check overall format
        if not InputValidator.DOMAIN_REGEX.match(domain):
            return False, "Domain format is invalid"
        
        # Check for localhost and special domains
        if domain.lower() in ['localhost', 'localhost.localdomain']:
            return False, "Localhost is not a valid domain for security checks"
        
        # Check for IP addresses disguised as domains
        try:
            ipaddress.ip_address(domain)
            return False, "IP addresses should not be provided as domains. Use IP-specific endpoints instead."
        except ValueError:
            pass  # Not an IP, which is good
        
        return True, None
    
    @staticmethod
    def validate_ip_address(ip: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate IP address (IPv4 or IPv6) with edge case handling.
        
        Args:
            ip: IP address to validate
            
        Returns:
            Tuple of (is_valid, error_message, ip_version)
        """
        # Check for None or empty
        if not ip:
            return False, "IP address cannot be empty", None
        
        # Check type
        if not isinstance(ip, str):
            return False, "IP address must be a string", None
        
        # Strip whitespace
        ip = ip.strip()
        
        # Check length
        if len(ip) > InputValidator.MAX_IP_LENGTH:
            return False, f"IP address exceeds maximum length of {InputValidator.MAX_IP_LENGTH} characters", None
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private/reserved addresses
            if ip_obj.is_private:
                return False, "Private IP addresses cannot be checked against public RBLs", None
            
            if ip_obj.is_loopback:
                return False, "Loopback addresses (127.0.0.1, ::1) are not valid for security checks", None
            
            if ip_obj.is_reserved:
                return False, "Reserved IP addresses are not valid for security checks", None
            
            if ip_obj.is_multicast:
                return False, "Multicast addresses are not valid for security checks", None
            
            # Determine version
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return True, None, "IPv4"
            else:
                return True, None, "IPv6"
                
        except ValueError as e:
            return False, f"Invalid IP address format: {str(e)}", None
    
    @staticmethod
    def validate_hostname(hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Validate hostname (can be domain or IP).
        
        Args:
            hostname: Hostname to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check for None or empty
        if not hostname:
            return False, "Hostname cannot be empty"
        
        # Check type
        if not isinstance(hostname, str):
            return False, "Hostname must be a string"
        
        # Strip whitespace
        hostname = hostname.strip()
        
        # Try as IP first
        is_valid_ip, _, _ = InputValidator.validate_ip_address(hostname)
        if is_valid_ip:
            return True, None
        
        # Try as domain
        is_valid_domain, error = InputValidator.validate_domain(hostname)
        if is_valid_domain:
            return True, None
        
        return False, f"Invalid hostname: {error}"
    
    @staticmethod
    def validate_dkim_selector(selector: str) -> Tuple[bool, Optional[str]]:
        """
        Validate DKIM selector.
        
        Args:
            selector: DKIM selector to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check for None or empty
        if not selector:
            return False, "DKIM selector cannot be empty"
        
        # Check type
        if not isinstance(selector, str):
            return False, "DKIM selector must be a string"
        
        # Strip whitespace
        selector = selector.strip()
        
        # Check length
        if len(selector) > 63:
            return False, "DKIM selector exceeds maximum length of 63 characters"
        
        # Check format (alphanumeric, hyphens, underscores)
        if not re.match(r'^[a-zA-Z0-9_-]+$', selector):
            return False, "DKIM selector contains invalid characters (only alphanumeric, hyphens, and underscores allowed)"
        
        return True, None
    
    @staticmethod
    def sanitize_domain(domain: str) -> str:
        """
        Sanitize domain input by removing common issues.
        
        Args:
            domain: Domain to sanitize
            
        Returns:
            Sanitized domain
        """
        if not domain:
            return domain
        
        # Strip whitespace
        domain = domain.strip()
        
        # Remove protocol if present
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in domain and not domain.count(':') > 1:  # Not IPv6
            domain = domain.split(':')[0]
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        # Remove www. prefix if present
        if domain.lower().startswith('www.'):
            domain = domain[4:]
        
        # Convert to lowercase
        domain = domain.lower()
        
        return domain
    
    @staticmethod
    def validate_timeout(timeout: float, min_val: float = 0.5, max_val: float = 30.0) -> Tuple[bool, Optional[str]]:
        """
        Validate timeout value.
        
        Args:
            timeout: Timeout value to validate
            min_val: Minimum allowed timeout
            max_val: Maximum allowed timeout
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            timeout_float = float(timeout)
            
            if timeout_float < min_val:
                return False, f"Timeout must be at least {min_val} seconds"
            
            if timeout_float > max_val:
                return False, f"Timeout cannot exceed {max_val} seconds"
            
            return True, None
            
        except (ValueError, TypeError):
            return False, "Timeout must be a valid number"
