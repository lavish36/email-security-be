import dns.resolver
import dns.reversename
import dns.exception
import re
import requests
from typing import List, Dict, Optional, Tuple, Any
from app.config import settings


class DNSResolver:
    """DNS resolution utility class."""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = settings.dns_timeout
        self.resolver.lifetime = settings.dns_timeout
        # Optional custom nameservers from config
        if getattr(settings, 'dns_nameservers', None):
            try:
                ns = [n.strip() for n in settings.dns_nameservers.split(',') if n.strip()]
                if ns:
                    self.resolver.nameservers = ns
            except Exception:
                pass
        
    def resolve_txt(self, domain: str) -> List[str]:
        """Resolve TXT records for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(answer).strip('"') for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.resolver.LifetimeTimeout:
            # Return None to indicate timeout, not empty list
            return None
        except dns.exception.DNSException:
            return []

    def resolve_txt_with_fallback(self, domain: str) -> List[str]:
        """Resolve TXT with fallback retries and public resolvers to reduce timeouts."""
        # Primary attempt
        result = self.resolve_txt(domain)
        if result is not None:
            return result
        # Timeout: try fallbacks
        fallback_nameservers = [['1.1.1.1', '1.0.0.1'], ['8.8.8.8', '8.8.4.4']]
        for names in fallback_nameservers:
            try:
                r = dns.resolver.Resolver()
                r.timeout = settings.dns_timeout
                r.lifetime = settings.dns_timeout
                r.nameservers = names
                answers = r.resolve(domain, 'TXT')
                return [str(answer).strip('"') for answer in answers]
            except dns.resolver.LifetimeTimeout:
                continue
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except dns.exception.DNSException:
                continue
        return None
    
    def resolve_mx(self, domain: str) -> List[Dict[str, Any]]:
        """Resolve MX records for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            for answer in answers:
                mx_records.append({
                    'preference': answer.preference,
                    'exchange': str(answer.exchange).rstrip('.'),
                    'priority': answer.preference
                })
            return sorted(mx_records, key=lambda x: x['preference'])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return []
    
    def resolve_a(self, domain: str) -> List[str]:
        """Resolve A records for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return []
    
    def resolve_aaaa(self, domain: str) -> List[str]:
        """Resolve AAAA records for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return []
    
    def resolve_ns(self, domain: str) -> List[str]:
        """Resolve NS records for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(answer).rstrip('.') for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return []
    
    def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC status for a domain."""
        try:
            # Check for DNSKEY records
            dnskey_records = []
            try:
                dnskey_answers = self.resolver.resolve(domain, 'DNSKEY')
                dnskey_records = [str(answer) for answer in dnskey_answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
            
            # Check for DS (Delegation Signer) records
            ds_records = []
            try:
                ds_answers = self.resolver.resolve(domain, 'DS')
                ds_records = [str(answer) for answer in ds_answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
            
            # Check for RRSIG records
            rrsig_records = []
            try:
                rrsig_answers = self.resolver.resolve(domain, 'RRSIG')
                rrsig_records = [str(answer) for answer in rrsig_answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
            
            # Determine DNSSEC status
            dnssec_enabled = bool(dnskey_records or ds_records or rrsig_records)
            
            return {
                'enabled': dnssec_enabled,
                'dnskey_records': len(dnskey_records),
                'ds_records': len(ds_records),
                'rrsig_records': len(rrsig_records),
                'status': 'enabled' if dnssec_enabled else 'disabled',
                'details': {
                    'dnskey': dnskey_records,
                    'ds': ds_records,
                    'rrsig': rrsig_records
                }
            }
            
        except Exception as e:
            return {
                'enabled': False,
                'dnskey_records': 0,
                'ds_records': 0,
                'rrsig_records': 0,
                'status': 'error',
                'error': str(e),
                'details': {}
            }


class SPFParser:
    """SPF record parser and validator."""
    
    @staticmethod
    def parse_spf_record(record: str) -> Dict[str, Any]:
        """Parse SPF record and extract components."""
        if not record.startswith('v=spf1'):
            return {
                'valid': False,
                'error': 'Record does not start with v=spf1'
            }
        
        # Remove the version prefix
        mechanisms = record[7:].strip()
        
        # Split mechanisms
        parts = mechanisms.split()
        
        result = {
            'valid': True,
            'mechanisms': [],
            'includes': [],
            'all_mechanism': None,
            'ips': [],
            'domains': [],
            'warnings': [],
            'lookup_count': 0,
            'strength': 'Unknown',
            'mechanism_details': []
        }
        
        lookup_count = 0
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            if part.startswith('include:'):
                domain = part[8:]
                result['includes'].append(domain)
                result['domains'].append(domain)
                result['mechanism_details'].append({
                    'type': 'include',
                    'value': domain,
                    'description': f'Authorizes emails from {domain}'
                })
                lookup_count += 1
            elif part.startswith('ip4:'):
                ip = part[4:]
                result['ips'].append(ip)
                result['mechanism_details'].append({
                    'type': 'ip4',
                    'value': ip,
                    'description': f'Authorizes IP address {ip}'
                })
            elif part.startswith('ip6:'):
                ip = part[4:]
                result['ips'].append(ip)
                result['mechanism_details'].append({
                    'type': 'ip6',
                    'value': ip,
                    'description': f'Authorizes IPv6 address {ip}'
                })
            elif part.startswith('a'):
                if ':' in part:
                    domain = part[2:]
                    result['domains'].append(domain)
                    result['mechanism_details'].append({
                        'type': 'a',
                        'value': domain,
                        'description': f'Authorizes A record of {domain}'
                    })
                else:
                    result['domains'].append('current')
                    result['mechanism_details'].append({
                        'type': 'a',
                        'value': 'current',
                        'description': 'Authorizes A record of current domain'
                    })
                lookup_count += 1
            elif part.startswith('mx'):
                if ':' in part:
                    domain = part[3:]
                    result['domains'].append(domain)
                    result['mechanism_details'].append({
                        'type': 'mx',
                        'value': domain,
                        'description': f'Authorizes MX records of {domain}'
                    })
                else:
                    result['domains'].append('current')
                    result['mechanism_details'].append({
                        'type': 'mx',
                        'value': 'current',
                        'description': 'Authorizes MX records of current domain'
                    })
                lookup_count += 1
            elif part.startswith('exists:'):
                domain = part[7:]
                result['domains'].append(domain)
                result['mechanism_details'].append({
                    'type': 'exists',
                    'value': domain,
                    'description': f'Checks if {domain} resolves to an A record'
                })
                lookup_count += 1
            elif part.startswith('ptr'):
                result['warnings'].append('Use of "ptr" mechanism is discouraged')
                result['mechanism_details'].append({
                    'type': 'ptr',
                    'value': part,
                    'description': 'Authorizes via reverse DNS (discouraged)'
                })
                lookup_count += 1
            elif part in ['all', '+all', '-all', '~all', '?all']:
                result['all_mechanism'] = part
                
                # Determine strength
                if part == '-all':
                    result['strength'] = 'Strong'
                    desc = 'Hard Fail: Unauthorized emails are rejected'
                elif part == '~all':
                    result['strength'] = 'Moderate'
                    desc = 'Soft Fail: Unauthorized emails are accepted but marked'
                elif part == '?all':
                    result['strength'] = 'Neutral'
                    desc = 'Neutral: No policy for unauthorized emails'
                else: # +all or all
                    result['strength'] = 'Weak'
                    desc = 'Pass: All emails are accepted (Insecure)'
                    
                result['mechanism_details'].append({
                    'type': 'all',
                    'value': part,
                    'description': desc
                })
            elif part.startswith('+') or part.startswith('-') or part.startswith('~') or part.startswith('?'):
                # Qualifier with mechanism
                result['mechanisms'].append(part)
                result['mechanism_details'].append({
                    'type': 'other',
                    'value': part,
                    'description': 'Custom mechanism'
                })
            else:
                result['mechanisms'].append(part)
                result['mechanism_details'].append({
                    'type': 'other',
                    'value': part,
                    'description': 'Unknown mechanism'
                })
        
        result['lookup_count'] = lookup_count
        
        # Validation checks
        if not result['all_mechanism']:
            result['warnings'].append('No "all" mechanism found - this is recommended')
            result['strength'] = 'Neutral' # Default to neutral if missing
        
        if result['all_mechanism'] == '+all':
            result['warnings'].append('Using "+all" allows all servers - consider using "-all" or "~all"')
        
        if lookup_count > 10:
            result['warnings'].append(f'Too many DNS lookups ({lookup_count} > 10) - may cause validation failures')
        
        return result
    
    @staticmethod
    def validate_spf_syntax(record: str) -> bool:
        """Validate SPF record syntax."""
        if not record.startswith('v=spf1'):
            return False
        
        # Basic syntax validation
        mechanisms = record[7:].strip()
        parts = mechanisms.split()
        
        for part in parts:
            if not re.match(r'^[+\-~?]?(all|include:|ip4:|ip6:|a|mx|exists:|ptr|exp:|redirect:)', part.split(':')[0] + ':' if ':' in part else part):
                return False
        
        return True


class DKIMParser:
    """DKIM record parser and validator."""
    
    @staticmethod
    def parse_dkim_record(record: str) -> Dict[str, Any]:
        """Parse DKIM record and extract components."""
        result = {
            'valid': False,
            'version': None,
            'algorithm': None,
            'key_type': None,
            'public_key': None,
            'key_size': None,
            'notes': None,
            'warnings': [],
            'security_profile': 'Unknown'
        }
        
        try:
            # Parse key=value pairs
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' not in part:
                    continue
                
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'v':
                    result['version'] = value
                elif key == 'k':
                    result['key_type'] = value
                elif key == 'p':
                    result['public_key'] = value
                elif key == 'n':
                    result['notes'] = value
                elif key == 't':
                    # Key type flags
                    pass
            
            # Validate required fields
            if result['public_key'] and result['key_type']:
                result['valid'] = True
                
                # Determine algorithm from key type
                if result['key_type'].lower() == 'rsa':
                    result['algorithm'] = 'rsa-sha256'
                    
                    # Estimate key size (rough calculation)
                    if result['public_key']:
                        # Base64 decoding length estimation: n * 6 / 8
                        # But simpler is just checking string length for now as a proxy
                        # Real implementation would decode base64 and check byte length
                        key_length = len(result['public_key'])
                        if key_length < 200:
                            result['key_size'] = 512
                        elif key_length < 400:
                            result['key_size'] = 1024
                        elif key_length < 800:
                            result['key_size'] = 2048
                        else:
                            result['key_size'] = 4096
                
                # Determine security profile
                if result['key_size']:
                    if result['key_size'] >= 2048:
                        result['security_profile'] = 'High'
                    elif result['key_size'] >= 1024:
                        result['security_profile'] = 'Medium'
                    else:
                        result['security_profile'] = 'Low'
                        result['warnings'].append('Key size is weak (< 1024 bits)')
                
                # Add warnings
                if result['key_size'] and result['key_size'] < 1024:
                    result['warnings'].append('Key size is less than 1024 bits - consider using 2048 bits or higher')
                
                if not result['version']:
                    result['warnings'].append('No version specified - DKIM version 1 is assumed')
            
        except Exception as e:
            result['warnings'].append(f'Error parsing DKIM record: {str(e)}')
        
        return result


class DMARCParser:
    """DMARC record parser and validator."""
    
    @staticmethod
    def parse_dmarc_record(record: str) -> Dict[str, Any]:
        """Parse DMARC record and extract components."""
        result = {
            'valid': False,
            'version': None,
            'policy': None,
            'subdomain_policy': None,
            'percentage': 100,
            'report_uri': [],
            'forensic_uri': [],
            'adkim': 'r',
            'aspf': 'r',
            'warnings': [],
            'policy_description': None,
            'alignment_description': {
                'spf': 'Relaxed (Default)',
                'dkim': 'Relaxed (Default)'
            }
        }
        
        try:
            # Parse key=value pairs
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' not in part:
                    continue
                
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'v':
                    result['version'] = value
                elif key == 'p':
                    result['policy'] = value
                    if value == 'reject':
                        result['policy_description'] = 'Reject: Emails that fail authentication are rejected'
                    elif value == 'quarantine':
                        result['policy_description'] = 'Quarantine: Emails that fail authentication are sent to spam'
                    elif value == 'none':
                        result['policy_description'] = 'None: Monitoring mode only, no action taken on failure'
                elif key == 'sp':
                    result['subdomain_policy'] = value
                elif key == 'pct':
                    try:
                        result['percentage'] = int(value)
                    except ValueError:
                        result['warnings'].append(f'Invalid percentage value: {value}')
                elif key == 'rua':
                    result['report_uri'] = [uri.strip() for uri in value.split(',')]
                elif key == 'ruf':
                    result['forensic_uri'] = [uri.strip() for uri in value.split(',')]
                elif key == 'adkim':
                    result['adkim'] = value
                    if value == 's':
                        result['alignment_description']['dkim'] = 'Strict: DKIM domain must exactly match the From domain'
                    else:
                        result['alignment_description']['dkim'] = 'Relaxed: DKIM domain can be a subdomain of the From domain'
                elif key == 'aspf':
                    result['aspf'] = value
                    if value == 's':
                        result['alignment_description']['spf'] = 'Strict: SPF Return-Path must exactly match the From domain'
                    else:
                        result['alignment_description']['spf'] = 'Relaxed: SPF Return-Path can be a subdomain of the From domain'
            
            # Validation
            if result['version'] == 'DMARC1':
                result['valid'] = True
            else:
                result['warnings'].append('Invalid or missing DMARC version')
            
            if not result['policy']:
                result['warnings'].append('No DMARC policy specified')
            
            if result['percentage'] < 0 or result['percentage'] > 100:
                result['warnings'].append('Percentage must be between 0 and 100')
            
            if result['adkim'] not in ['r', 's']:
                result['warnings'].append('Invalid adkim value - must be "r" or "s"')
            
            if result['aspf'] not in ['r', 's']:
                result['warnings'].append('Invalid aspf value - must be "r" or "s"')
            
        except Exception as e:
            result['warnings'].append(f'Error parsing DMARC record: {str(e)}')
        
        return result


class MTASTSParser:
    """MTA-STS record and policy parser."""
    
    @staticmethod
    def parse_mtasts_record(record: str) -> Dict[str, Any]:
        """Parse MTA-STS DNS TXT record."""
        result = {
            'valid': False,
            'version': None,
            'id': None,
            'warnings': []
        }
        
        try:
            # Parse key=value pairs
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' not in part:
                    continue
                
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'v':
                    result['version'] = value
                elif key == 'id':
                    result['id'] = value
            
            # Validation
            if result['version'] == 'STSv1':
                result['valid'] = True
            else:
                result['warnings'].append('Invalid or missing MTA-STS version')
            
            if not result['id']:
                result['warnings'].append('No policy ID specified')
            
        except Exception as e:
            result['warnings'].append(f'Error parsing MTA-STS record: {str(e)}')
        
        return result
    
    @staticmethod
    def parse_mtasts_policy(policy_content: str) -> Dict[str, Any]:
        """Parse MTA-STS policy file content."""
        result = {
            'valid': False,
            'version': None,
            'mode': None,
            'max_age': None,
            'mx_records': [],
            'include_subdomains': False,
            'warnings': []
        }
        
        try:
            lines = policy_content.strip().split('\n')
            in_mx_section = False
            
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
                    elif key == 'mode':
                        result['mode'] = value
                    elif key == 'max_age':
                        try:
                            result['max_age'] = int(value)
                        except ValueError:
                            result['warnings'].append(f'Invalid max_age value: {value}')
                    elif key == 'mx':
                        in_mx_section = True
                        continue
                    elif key == 'subdomains':
                        result['include_subdomains'] = value.lower() == 'true'
                
                # Handle MX records (indented lines)
                elif in_mx_section and line.startswith('-'):
                    mx_record = line[1:].strip()
                    if mx_record:
                        result['mx_records'].append(mx_record)
                elif in_mx_section and not line.startswith(' '):
                    in_mx_section = False
            
            # Validation
            if result['version'] == 'STSv1':
                result['valid'] = True
            else:
                result['warnings'].append('Invalid or missing version')
            
            if not result['mode']:
                result['warnings'].append('No mode specified')
            elif result['mode'] not in ['testing', 'enforce', 'none']:
                result['warnings'].append('Invalid mode - must be testing, enforce, or none')
            
            if not result['max_age']:
                result['warnings'].append('No max_age specified')
            elif result['max_age'] < 300 or result['max_age'] > 31536000:
                result['warnings'].append('Max age should be between 300 and 31536000 seconds')
            
        except Exception as e:
            result['warnings'].append(f'Error parsing MTA-STS policy: {str(e)}')
        
        return result
    
    @staticmethod
    def fetch_mtasts_policy(domain: str) -> Optional[str]:
        """Fetch MTA-STS policy file from domain."""
        try:
            # Try HTTPS first
            url = f'https://mta-sts.{domain}/.well-known/mta-sts.txt'
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.text
            
            # Try HTTP as fallback (not recommended but some domains might use it)
            url = f'http://mta-sts.{domain}/.well-known/mta-sts.txt'
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.text
            
            return None
            
        except Exception:
            return None


class TLSRPTParser:
    """TLS-RPT record parser."""
    
    @staticmethod
    def parse_tlsrpt_record(record: str) -> Dict[str, Any]:
        """Parse TLS-RPT DNS TXT record."""
        result = {
            'valid': False,
            'version': None,
            'rua': [],
            'include_subdomains': False,
            'warnings': []
        }
        
        try:
            # Parse key=value pairs
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' not in part:
                    continue
                
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'v':
                    result['version'] = value
                elif key == 'rua':
                    result['rua'] = [uri.strip() for uri in value.split(',')]
                elif key == 'subdomains':
                    result['include_subdomains'] = value.lower() == 'true'
            
            # Validation
            if result['version'] == 'TLSRPTv1':
                result['valid'] = True
            else:
                result['warnings'].append('Invalid or missing TLS-RPT version')
            
            if not result['rua']:
                result['warnings'].append('No report URIs specified')
            
        except Exception as e:
            result['warnings'].append(f'Error parsing TLS-RPT record: {str(e)}')
        
        return result


# Global DNS resolver instance
dns_resolver = DNSResolver() 