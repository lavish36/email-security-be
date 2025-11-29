"""
Comprehensive test suite for Domain Security API.
Tests parsers, validators, and edge cases.
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.utils.dns_utils import SPFParser, DKIMParser, DMARCParser
from app.utils.input_validation import InputValidator


class TestSPFParser:
    """Test SPF record parsing and validation."""
    
    def test_valid_spf_strong(self):
        """Test strong SPF record with -all."""
        record = "v=spf1 include:_spf.google.com -all"
        result = SPFParser.parse_spf_record(record)
        
        assert result['valid'] is True
        assert result['strength'] == 'Strong'
        assert result['all_mechanism'] == '-all'
        assert len(result['includes']) == 1
        assert result['lookup_count'] == 1
    
    def test_valid_spf_moderate(self):
        """Test moderate SPF record with ~all."""
        record = "v=spf1 ip4:192.0.2.0/24 ~all"
        result = SPFParser.parse_spf_record(record)
        
        assert result['valid'] is True
        assert result['strength'] == 'Moderate'
        assert result['all_mechanism'] == '~all'
    
    def test_valid_spf_weak(self):
        """Test weak SPF record with +all."""
        record = "v=spf1 +all"
        result = SPFParser.parse_spf_record(record)
        
        assert result['valid'] is True
        assert result['strength'] == 'Weak'
        assert '+all' in result['warnings'][0]
    
    def test_spf_too_many_lookups(self):
        """Test SPF with too many DNS lookups."""
        includes = " ".join([f"include:spf{i}.example.com" for i in range(12)])
        record = f"v=spf1 {includes} -all"
        result = SPFParser.parse_spf_record(record)
        
        assert result['lookup_count'] > 10
        assert any('Too many DNS lookups' in w for w in result['warnings'])
    
    def test_spf_no_all_mechanism(self):
        """Test SPF without all mechanism."""
        record = "v=spf1 include:_spf.google.com"
        result = SPFParser.parse_spf_record(record)
        
        assert result['all_mechanism'] is None
        assert any('No "all" mechanism found' in w for w in result['warnings'])
    
    def test_invalid_spf_no_version(self):
        """Test invalid SPF without version."""
        record = "include:_spf.google.com -all"
        result = SPFParser.parse_spf_record(record)
        
        assert result['valid'] is False
        assert 'error' in result
    
    def test_spf_mechanism_details(self):
        """Test SPF mechanism details generation."""
        record = "v=spf1 include:_spf.google.com ip4:192.0.2.1 mx -all"
        result = SPFParser.parse_spf_record(record)
        
        assert len(result['mechanism_details']) > 0
        assert any(d['type'] == 'include' for d in result['mechanism_details'])
        assert any(d['type'] == 'ip4' for d in result['mechanism_details'])
        assert any(d['type'] == 'all' for d in result['mechanism_details'])


class TestDKIMParser:
    """Test DKIM record parsing and validation."""
    
    def test_valid_dkim_strong(self):
        """Test strong DKIM with 2048-bit key."""
        record = "v=DKIM1; k=rsa; p=" + "A" * 400  # Simulates 2048-bit
        result = DKIMParser.parse_dkim_record(record)
        
        assert result['valid'] is True
        assert result['security_profile'] == 'High'
        assert result['key_size'] == 2048
    
    def test_valid_dkim_medium(self):
        """Test medium DKIM with 1024-bit key."""
        record = "v=DKIM1; k=rsa; p=" + "A" * 200  # Simulates 1024-bit
        result = DKIMParser.parse_dkim_record(record)
        
        assert result['valid'] is True
        assert result['security_profile'] == 'Medium'
        assert result['key_size'] == 1024
    
    def test_valid_dkim_weak(self):
        """Test weak DKIM with 512-bit key."""
        record = "v=DKIM1; k=rsa; p=" + "A" * 100  # Simulates 512-bit
        result = DKIMParser.parse_dkim_record(record)
        
        assert result['valid'] is True
        assert result['security_profile'] == 'Low'
        assert len(result['warnings']) > 0


class TestDMARCParser:
    """Test DMARC record parsing and validation."""
    
    def test_valid_dmarc_reject(self):
        """Test DMARC with reject policy."""
        record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        result = DMARCParser.parse_dmarc_record(record)
        
        assert result['valid'] is True
        assert result['policy'] == 'reject'
        assert 'Reject' in result['policy_description']
    
    def test_valid_dmarc_quarantine(self):
        """Test DMARC with quarantine policy."""
        record = "v=DMARC1; p=quarantine"
        result = DMARCParser.parse_dmarc_record(record)
        
        assert result['valid'] is True
        assert result['policy'] == 'quarantine'
        assert 'Quarantine' in result['policy_description']
    
    def test_valid_dmarc_none(self):
        """Test DMARC with none policy (monitoring)."""
        record = "v=DMARC1; p=none"
        result = DMARCParser.parse_dmarc_record(record)
        
        assert result['valid'] is True
        assert result['policy'] == 'none'
        assert 'Monitoring' in result['policy_description']
    
    def test_dmarc_strict_alignment(self):
        """Test DMARC with strict alignment."""
        record = "v=DMARC1; p=reject; adkim=s; aspf=s"
        result = DMARCParser.parse_dmarc_record(record)
        
        assert result['adkim'] == 's'
        assert result['aspf'] == 's'
        assert 'Strict' in result['alignment_description']['dkim']
        assert 'Strict' in result['alignment_description']['spf']
    
    def test_dmarc_relaxed_alignment(self):
        """Test DMARC with relaxed alignment (default)."""
        record = "v=DMARC1; p=reject"
        result = DMARCParser.parse_dmarc_record(record)
        
        assert result['adkim'] == 'r'
        assert result['aspf'] == 'r'
        assert 'Relaxed' in result['alignment_description']['dkim']


class TestInputValidator:
    """Test input validation utilities."""
    
    def test_valid_domain(self):
        """Test valid domain validation."""
        is_valid, error = InputValidator.validate_domain("example.com")
        assert is_valid is True
        assert error is None
    
    def test_valid_subdomain(self):
        """Test valid subdomain validation."""
        is_valid, error = InputValidator.validate_domain("mail.example.com")
        assert is_valid is True
        assert error is None
    
    def test_invalid_domain_empty(self):
        """Test empty domain validation."""
        is_valid, error = InputValidator.validate_domain("")
        assert is_valid is False
        assert "empty" in error.lower()
    
    def test_invalid_domain_too_long(self):
        """Test domain that's too long."""
        long_domain = "a" * 300 + ".com"
        is_valid, error = InputValidator.validate_domain(long_domain)
        assert is_valid is False
        assert "maximum length" in error.lower()
    
    def test_invalid_domain_starts_with_dot(self):
        """Test domain starting with dot."""
        is_valid, error = InputValidator.validate_domain(".example.com")
        assert is_valid is False
        assert "dot" in error.lower()
    
    def test_invalid_domain_ends_with_dot(self):
        """Test domain ending with dot."""
        is_valid, error = InputValidator.validate_domain("example.com.")
        assert is_valid is False
        assert "dot" in error.lower()
    
    def test_invalid_domain_consecutive_dots(self):
        """Test domain with consecutive dots."""
        is_valid, error = InputValidator.validate_domain("example..com")
        assert is_valid is False
        assert "consecutive" in error.lower()
    
    def test_invalid_domain_localhost(self):
        """Test localhost rejection."""
        is_valid, error = InputValidator.validate_domain("localhost")
        assert is_valid is False
        assert "localhost" in error.lower()
    
    def test_valid_ipv4(self):
        """Test valid IPv4 validation."""
        is_valid, error, version = InputValidator.validate_ip_address("8.8.8.8")
        assert is_valid is True
        assert error is None
        assert version == "IPv4"
    
    def test_valid_ipv6(self):
        """Test valid IPv6 validation."""
        is_valid, error, version = InputValidator.validate_ip_address("2001:4860:4860::8888")
        assert is_valid is True
        assert error is None
        assert version == "IPv6"
    
    def test_invalid_ip_private(self):
        """Test private IP rejection."""
        is_valid, error, _ = InputValidator.validate_ip_address("192.168.1.1")
        assert is_valid is False
        assert "private" in error.lower()
    
    def test_invalid_ip_loopback(self):
        """Test loopback IP rejection."""
        is_valid, error, _ = InputValidator.validate_ip_address("127.0.0.1")
        assert is_valid is False
        assert error is not None
    
    def test_invalid_ip_format(self):
        """Test invalid IP format."""
        is_valid, error, _ = InputValidator.validate_ip_address("999.999.999.999")
        assert is_valid is False
        assert "invalid" in error.lower()
    
    def test_sanitize_domain_with_protocol(self):
        """Test domain sanitization with protocol."""
        sanitized = InputValidator.sanitize_domain("https://example.com")
        assert sanitized == "example.com"
    
    def test_sanitize_domain_with_www(self):
        """Test domain sanitization with www."""
        sanitized = InputValidator.sanitize_domain("www.example.com")
        assert sanitized == "example.com"
    
    def test_sanitize_domain_with_port(self):
        """Test domain sanitization with port."""
        sanitized = InputValidator.sanitize_domain("example.com:8080")
        assert sanitized == "example.com"
    
    def test_sanitize_domain_uppercase(self):
        """Test domain sanitization converts to lowercase."""
        sanitized = InputValidator.sanitize_domain("EXAMPLE.COM")
        assert sanitized == "example.com"
    
    def test_valid_dkim_selector(self):
        """Test valid DKIM selector."""
        is_valid, error = InputValidator.validate_dkim_selector("default")
        assert is_valid is True
        assert error is None
    
    def test_valid_dkim_selector_with_numbers(self):
        """Test valid DKIM selector with numbers."""
        is_valid, error = InputValidator.validate_dkim_selector("selector1")
        assert is_valid is True
        assert error is None
    
    def test_invalid_dkim_selector_empty(self):
        """Test empty DKIM selector."""
        is_valid, error = InputValidator.validate_dkim_selector("")
        assert is_valid is False
        assert "empty" in error.lower()
    
    def test_invalid_dkim_selector_special_chars(self):
        """Test DKIM selector with invalid characters."""
        is_valid, error = InputValidator.validate_dkim_selector("selector@123")
        assert is_valid is False
        assert "invalid characters" in error.lower()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
