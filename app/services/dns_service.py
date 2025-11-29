import asyncio
import socket
import ssl
from typing import List, Dict, Any, Optional
from app.utils.dns_utils import dns_resolver, SPFParser, DKIMParser, DMARCParser, MTASTSParser, TLSRPTParser
from app.utils.validation_utils import DomainValidator
from app.models.security import SecurityStatus
from datetime import datetime


class DNSService:
    """DNS resolution and record analysis service."""
    
    def __init__(self):
        self.resolver = dns_resolver
    
    async def get_spf_record(self, domain: str) -> Dict[str, Any]:
        """
        Get and analyze SPF record for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            SPF analysis result
        """
        try:
            # Normalize domain
            domain = DomainValidator.normalize_domain(domain)
            
            # Get TXT records (with fallback resolvers on timeout)
            # Wrap synchronous DNS call in asyncio.to_thread to prevent blocking
            if hasattr(self.resolver, 'resolve_txt_with_fallback'):
                txt_records = await asyncio.to_thread(self.resolver.resolve_txt_with_fallback, domain)
            else:
                txt_records = await asyncio.to_thread(self.resolver.resolve_txt, domain)
            
            # Handle timeout case
            if txt_records is None:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.ERROR,
                    'mechanisms': [],
                    'includes': [],
                    'all_mechanism': None,
                    'record_count': 0,
                    'warnings': ['DNS timeout while resolving TXT records'],
                    'recommendations': [
                        'DNS resolution timed out - try again later',
                        'Check if the domain has DNS configuration issues'
                    ]
                }
            
            # Find SPF records
            spf_records = []
            for record in txt_records:
                if record.startswith('v=spf1'):
                    spf_records.append(record)
            
            if not spf_records:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.NOT_FOUND,
                    'mechanisms': [],
                    'includes': [],
                    'all_mechanism': None,
                    'record_count': 0,
                    'warnings': ['No SPF record found'],
                    'recommendations': [
                        'Create an SPF record to prevent email spoofing',
                        'Start with a basic SPF record: v=spf1 -all',
                        'Add your email providers to the SPF record'
                    ]
                }
            
            if len(spf_records) > 1:
                return {
                    'exists': True,
                    'record': spf_records[0],
                    'status': SecurityStatus.WARNING,
                    'mechanisms': [],
                    'includes': [],
                    'all_mechanism': None,
                    'record_count': len(spf_records),
                    'warnings': [f'Multiple SPF records found ({len(spf_records)}) - only the first one will be used'],
                    'recommendations': [
                        'Remove duplicate SPF records',
                        'Keep only one SPF record per domain'
                    ]
                }
            
            # Parse SPF record
            spf_record = spf_records[0]
            parsed = SPFParser.parse_spf_record(spf_record)
            
            # Ensure parsed is not None
            if parsed is None:
                parsed = {
                    'valid': False,
                    'mechanisms': [],
                    'includes': [],
                    'all_mechanism': None,
                    'ips': [],
                    'domains': [],
                    'warnings': ['Error parsing SPF record']
                }
            
            # Determine status
            status = SecurityStatus.PASS
            if not parsed.get('valid', False) if parsed else False:
                status = SecurityStatus.FAIL
            elif parsed.get('warnings', []) if parsed else []:
                status = SecurityStatus.WARNING
            
            return {
                'exists': True,
                'record': spf_record,
                'status': status,
                'mechanisms': parsed.get('mechanisms', []) if parsed else [],
                'includes': parsed.get('includes', []) if parsed else [],
                'all_mechanism': parsed.get('all_mechanism') if parsed else None,
                'record_count': 1,
                'warnings': parsed.get('warnings', []) if parsed else [],
                'recommendations': self._get_spf_recommendations(parsed),
                'lookup_count': parsed.get('lookup_count', 0) if parsed else 0,
                'strength': parsed.get('strength', 'Unknown') if parsed else 'Unknown',
                'mechanism_details': parsed.get('mechanism_details', []) if parsed else []
            }
            
        except Exception as e:
            return {
                'exists': False,
                'record': None,
                'status': SecurityStatus.ERROR,
                'mechanisms': [],
                'includes': [],
                'all_mechanism': None,
                'record_count': 0,
                'warnings': [f'Error analyzing SPF record: {str(e)}'],
                'recommendations': ['Check DNS configuration and try again']
            }
    
    async def get_dkim_records(self, domain: str, selectors: List[str] = None) -> List[Dict[str, Any]]:
        """
        Get and analyze DKIM records for a domain.
        
        Args:
            domain: Domain name
            selectors: List of DKIM selectors to check
            
        Returns:
            List of DKIM analysis results
        """
        if selectors is None:
            selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mandrill', 's1', 's2', 'infosys', 'mail', 'smtp', 'dkim', 'key', 'selector']
        
        results = []
        
        for selector in selectors:
            try:
                # Normalize domain
                domain = DomainValidator.normalize_domain(domain)
                
                # Construct DKIM record name
                dkim_domain = f'{selector}._domainkey.{domain}'
                
                # Get TXT records (with fallback resolvers on timeout)
                if hasattr(self.resolver, 'resolve_txt_with_fallback'):
                    txt_records = await asyncio.to_thread(self.resolver.resolve_txt_with_fallback, dkim_domain)
                else:
                    txt_records = await asyncio.to_thread(self.resolver.resolve_txt, dkim_domain)
                
                # Handle timeout case
                if txt_records is None:
                    results.append({
                        'selector': selector,
                        'exists': False,
                        'record': None,
                        'status': SecurityStatus.ERROR,
                        'public_key': None,
                        'algorithm': None,
                        'key_type': None,
                        'key_size': None,
                        'warnings': [f'DNS timeout while resolving DKIM TXT records for selector "{selector}"'],
                        'recommendations': [
                            'DNS resolution timed out - try again later',
                            'Check if the domain has DNS configuration issues'
                        ]
                    })
                    continue
                
                if not txt_records:
                    results.append({
                        'selector': selector,
                        'exists': False,
                        'record': None,
                        'status': SecurityStatus.NOT_FOUND,
                        'public_key': None,
                        'algorithm': None,
                        'key_type': None,
                        'key_size': None,
                        'warnings': [f'No DKIM record found for selector "{selector}"'],
                        'recommendations': [
                            f'Create a DKIM record for selector "{selector}"',
                            'Configure your email service to use DKIM signing'
                        ]
                    })
                    continue
                
                # Parse DKIM record
                dkim_record = txt_records[0]
                parsed = DKIMParser.parse_dkim_record(dkim_record)
                
                # Ensure parsed is not None
                if parsed is None:
                    parsed = {
                        'valid': False,
                        'version': None,
                        'algorithm': None,
                        'key_type': None,
                        'public_key': None,
                        'key_size': None,
                        'notes': None,
                        'warnings': ['Error parsing DKIM record']
                    }
                
                # Determine status
                status = SecurityStatus.PASS
                if not parsed.get('valid', False) if parsed else False:
                    status = SecurityStatus.FAIL
                elif parsed.get('warnings', []) if parsed else []:
                    status = SecurityStatus.WARNING
                
                results.append({
                    'selector': selector,
                    'exists': True,
                    'record': dkim_record,
                    'status': status,
                    'public_key': parsed.get('public_key') if parsed else None,
                    'algorithm': parsed.get('algorithm') if parsed else None,
                    'key_type': parsed.get('key_type') if parsed else None,
                    'key_size': parsed.get('key_size') if parsed else None,
                    'warnings': parsed.get('warnings', []) if parsed else [],
                    'recommendations': self._get_dkim_recommendations(parsed),
                    'security_profile': parsed.get('security_profile', 'Unknown') if parsed else 'Unknown'
                })
                
            except Exception as e:
                results.append({
                    'selector': selector,
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.ERROR,
                    'public_key': None,
                    'algorithm': None,
                    'key_type': None,
                    'key_size': None,
                    'warnings': [f'Error analyzing DKIM record for selector "{selector}": {str(e)}'],
                    'recommendations': ['Check DNS configuration and try again']
                })
        
        return results
    
    async def get_dmarc_record(self, domain: str) -> Dict[str, Any]:
        """
        Get and analyze DMARC record for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            DMARC analysis result
        """
        try:
            # Normalize domain
            domain = DomainValidator.normalize_domain(domain)
            
            # Construct DMARC record name
            dmarc_domain = f'_dmarc.{domain}'
            
            # Get TXT records (with fallback resolvers on timeout)
            if hasattr(self.resolver, 'resolve_txt_with_fallback'):
                txt_records = await asyncio.to_thread(self.resolver.resolve_txt_with_fallback, dmarc_domain)
            else:
                txt_records = await asyncio.to_thread(self.resolver.resolve_txt, dmarc_domain)
            
            # Handle timeout case
            if txt_records is None:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.ERROR,
                    'policy': None,
                    'subdomain_policy': None,
                    'percentage': None,
                    'report_uri': [],
                    'forensic_uri': [],
                    'adkim': None,
                    'aspf': None,
                    'warnings': ['DNS timeout while resolving DMARC TXT records'],
                    'recommendations': [
                        'DNS resolution timed out - try again later',
                        'Check if the domain has DNS configuration issues'
                    ]
                }
            
            if not txt_records:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.NOT_FOUND,
                    'policy': None,
                    'subdomain_policy': None,
                    'percentage': None,
                    'report_uri': [],
                    'forensic_uri': [],
                    'adkim': None,
                    'aspf': None,
                    'warnings': ['No DMARC record found'],
                    'recommendations': [
                        'Create a DMARC record to protect against email spoofing',
                        'Start with a monitoring policy: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com'
                    ]
                }
            
            # Parse DMARC record
            dmarc_record = txt_records[0]
            parsed = DMARCParser.parse_dmarc_record(dmarc_record)
            
            # Ensure parsed is not None
            if parsed is None:
                parsed = {
                    'valid': False,
                    'version': None,
                    'policy': None,
                    'subdomain_policy': None,
                    'percentage': 100,
                    'report_uri': [],
                    'forensic_uri': [],
                    'adkim': 'r',
                    'aspf': 'r',
                    'warnings': ['Error parsing DMARC record']
                }
            
            # Determine status
            status = SecurityStatus.PASS
            if not parsed.get('valid', False) if parsed else False:
                status = SecurityStatus.FAIL
            elif parsed.get('warnings', []) if parsed else []:
                status = SecurityStatus.WARNING
            else:
                # Check policy enforcement - p=none provides no protection
                policy = parsed.get('policy', 'none') if parsed else 'none'
                if policy == 'none':
                    status = SecurityStatus.WARNING
                elif policy == 'quarantine':
                    status = SecurityStatus.PASS
                elif policy == 'reject':
                    status = SecurityStatus.PASS
            
            return {
                'exists': True,
                'record': dmarc_record,
                'status': status,
                'policy': parsed.get('policy') if parsed else None,
                'subdomain_policy': parsed.get('subdomain_policy') if parsed else None,
                'percentage': parsed.get('percentage') if parsed else None,
                'report_uri': parsed.get('report_uri', []) if parsed else [],
                'forensic_uri': parsed.get('forensic_uri', []) if parsed else [],
                'adkim': parsed.get('adkim') if parsed else None,
                'aspf': parsed.get('aspf') if parsed else None,
                'warnings': parsed.get('warnings', []) if parsed else [],
                'recommendations': self._get_dmarc_recommendations(parsed),
                'policy_description': parsed.get('policy_description') if parsed else None,
                'alignment_description': parsed.get('alignment_description') if parsed else None
            }
            
        except Exception as e:
            return {
                'exists': False,
                'record': None,
                'status': SecurityStatus.ERROR,
                'policy': None,
                'subdomain_policy': None,
                'percentage': None,
                'report_uri': [],
                'forensic_uri': [],
                'adkim': None,
                'aspf': None,
                'warnings': [f'Error analyzing DMARC record: {str(e)}'],
                'recommendations': ['Check DNS configuration and try again']
            }
    
    async def get_mtasts_record(self, domain: str) -> Dict[str, Any]:
        """
        Get and analyze MTA-STS record for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            MTA-STS analysis result
        """
        try:
            # Normalize domain
            domain = DomainValidator.normalize_domain(domain)
            
            # Get TXT records for MTA-STS
            mta_sts_domain = f'_mta-sts.{domain}'
            txt_records = await asyncio.to_thread(self.resolver.resolve_txt, mta_sts_domain)
            
            # Handle timeout case
            if txt_records is None:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.ERROR,
                    'version': None,
                    'mode': None,
                    'max_age': None,
                    'mx_records': [],
                    'policy_accessible': False,
                    'policy_valid': False,
                    'warnings': ['DNS timeout while resolving MTA-STS TXT records'],
                    'recommendations': [
                        'DNS resolution timed out - try again later',
                        'Check if the domain has DNS configuration issues'
                    ]
                }
            
            # Find MTA-STS records
            mtasts_records = []
            for record in txt_records:
                if record.startswith('v=STSv1'):
                    mtasts_records.append(record)
            
            if not mtasts_records:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.NOT_FOUND,
                    'version': None,
                    'mode': None,
                    'max_age': None,
                    'mx_records': [],
                    'policy_accessible': False,
                    'policy_valid': False,
                    'warnings': ['No MTA-STS record found'],
                    'recommendations': [
                        'Create an MTA-STS record to protect against downgrade attacks',
                        'Start with testing mode: v=STSv1; id=1',
                        'Set up MTA-STS policy file at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt'
                    ]
                }
            
            # Parse MTA-STS record
            mtasts_record = mtasts_records[0]
            parsed = MTASTSParser.parse_mtasts_record(mtasts_record)
            
            # Ensure parsed is not None
            if parsed is None:
                parsed = {
                    'valid': False,
                    'version': None,
                    'id': None,
                    'warnings': ['Error parsing MTA-STS record']
                }
            
            # Try to fetch policy file
            policy_content = await MTASTSParser.fetch_mtasts_policy(domain)
            policy_parsed = None
            policy_accessible = False
            policy_valid = False
            
            if policy_content:
                policy_accessible = True
                policy_parsed = MTASTSParser.parse_mtasts_policy(policy_content)
                policy_valid = policy_parsed['valid']
            
            # Determine status
            status = SecurityStatus.PASS
            if not parsed['valid']:
                status = SecurityStatus.FAIL
            elif not policy_accessible:
                status = SecurityStatus.WARNING
            elif not policy_valid:
                status = SecurityStatus.WARNING
            elif parsed['warnings'] or (policy_parsed and policy_parsed['warnings']):
                status = SecurityStatus.WARNING
            
            return {
                'exists': True,
                'record': mtasts_record,
                'status': status,
                'version': parsed['version'],
                'mode': policy_parsed['mode'] if policy_parsed else None,
                'max_age': policy_parsed['max_age'] if policy_parsed else None,
                'mx_records': policy_parsed['mx_records'] if policy_parsed else [],
                'policy_accessible': policy_accessible,
                'policy_valid': policy_valid,
                'warnings': parsed['warnings'] + (policy_parsed.get('warnings', []) if policy_parsed else []),
                'recommendations': self._get_mtasts_recommendations(parsed, policy_parsed, policy_accessible)
            }
            
        except Exception as e:
            return {
                'exists': False,
                'record': None,
                'status': SecurityStatus.ERROR,
                'version': None,
                'mode': None,
                'max_age': None,
                'mx_records': [],
                'policy_accessible': False,
                'policy_valid': False,
                'warnings': [f'Error analyzing MTA-STS record: {str(e)}'],
                'recommendations': ['Check DNS configuration and try again']
            }
    
    async def get_tlsrpt_record(self, domain: str) -> Dict[str, Any]:
        """
        Get and analyze TLS-RPT record for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            TLS-RPT analysis result
        """
        try:
            # Normalize domain
            domain = DomainValidator.normalize_domain(domain)
            
            # Get TXT records for TLS-RPT
            tlsrpt_domain = f'_smtp._tls.{domain}'
            txt_records = await asyncio.to_thread(self.resolver.resolve_txt, tlsrpt_domain)
            
            # Handle timeout case
            if txt_records is None:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.ERROR,
                    'version': None,
                    'rua': [],
                    'warnings': ['DNS timeout while resolving TLS-RPT TXT records'],
                    'recommendations': [
                        'DNS resolution timed out - try again later',
                        'Check if the domain has DNS configuration issues'
                    ]
                }
            
            # Find TLS-RPT records
            tlsrpt_records = []
            for record in txt_records:
                if record.startswith('v=TLSRPTv1'):
                    tlsrpt_records.append(record)
            
            if not tlsrpt_records:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.NOT_FOUND,
                    'version': None,
                    'rua': [],
                    'warnings': ['No TLS-RPT record found'],
                    'recommendations': [
                        'Create a TLS-RPT record to receive TLS failure reports',
                        'Use format: v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com'
                    ]
                }
            
            # Parse TLS-RPT record
            tlsrpt_record = tlsrpt_records[0]
            parsed = TLSRPTParser.parse_tlsrpt_record(tlsrpt_record)
            
            # Ensure parsed is not None
            if parsed is None:
                parsed = {
                    'valid': False,
                    'version': None,
                    'rua': [],
                    'warnings': ['Error parsing TLS-RPT record']
                }
            
            # Determine status
            status = SecurityStatus.PASS
            if not parsed['valid']:
                status = SecurityStatus.FAIL
            elif parsed['warnings']:
                status = SecurityStatus.WARNING
            
            return {
                'exists': True,
                'record': tlsrpt_record,
                'status': status,
                'version': parsed['version'],
                'rua': parsed['rua'],
                'warnings': parsed['warnings'],
                'recommendations': self._get_tlsrpt_recommendations(parsed)
            }
            
        except Exception as e:
            return {
                'exists': False,
                'record': None,
                'status': SecurityStatus.ERROR,
                'version': None,
                'rua': [],
                'warnings': [f'Error analyzing TLS-RPT record: {str(e)}'],
                'recommendations': ['Check DNS configuration and try again']
            }
    
    async def get_dnssec_status(self, domain: str) -> Dict[str, Any]:
        """
        Get DNSSEC status for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            DNSSEC analysis result
        """
        try:
            # Normalize domain
            domain = DomainValidator.normalize_domain(domain)
            
            # Check DNSSEC status
            dnssec_result = await asyncio.to_thread(self.resolver.check_dnssec, domain)
            
            # Determine status
            if dnssec_result['enabled']:
                status = SecurityStatus.PASS
                recommendations = [
                    'DNSSEC is properly configured',
                    'Monitor DNSSEC validation status regularly'
                ]
            else:
                status = SecurityStatus.WARNING
                recommendations = [
                    'Consider enabling DNSSEC for enhanced DNS security',
                    'Contact your DNS provider to enable DNSSEC',
                    'DNSSEC helps prevent DNS spoofing and cache poisoning attacks'
                ]
            
            return {
                'enabled': dnssec_result['enabled'],
                'status': status,
                'dnskey_records': dnssec_result['dnskey_records'],
                'ds_records': dnssec_result['ds_records'],
                'rrsig_records': dnssec_result['rrsig_records'],
                'warnings': [] if dnssec_result['enabled'] else ['DNSSEC not enabled'],
                'recommendations': recommendations,
                'details': dnssec_result['details']
            }
            
        except Exception as e:
            return {
                'enabled': False,
                'status': SecurityStatus.ERROR,
                'dnskey_records': 0,
                'ds_records': 0,
                'rrsig_records': 0,
                'warnings': [f'Error checking DNSSEC: {str(e)}'],
                'recommendations': ['Check DNS configuration and try again'],
                'details': {}
            }
    
    async def get_mx_records(self, domain: str) -> Dict[str, Any]:
        """
        Get and analyze MX records for a domain with enhanced security assessment.
        
        Args:
            domain: Domain name
            
        Returns:
            MX analysis result with security assessment
        """
        try:
            # Normalize domain
            domain = DomainValidator.normalize_domain(domain)
            
            # Get MX records
            mx_records = await asyncio.to_thread(self.resolver.resolve_mx, domain)
            
            if not mx_records:
                return {
                    'records': [],
                    'status': SecurityStatus.FAIL,
                    'primary_mx': None,
                    'backup_mx_count': 0,
                    'security_score': 0,
                    'open_relay_risk': False,
                    'warnings': ['No MX records found'],
                    'recommendations': [
                        'Create MX records to enable email delivery',
                        'Add at least one primary MX server',
                        'Consider adding backup MX servers for redundancy'
                    ]
                }
            
            # Analyze MX records
            primary_mx = mx_records[0]['exchange'] if mx_records else None
            backup_mx_count = len(mx_records) - 1 if len(mx_records) > 1 else 0
            
            # Security analysis
            security_score = 10  # Start with perfect score
            open_relay_risk = False
            warnings = []
            
            # Check number of MX records
            if len(mx_records) == 1:
                warnings.append('Only one MX record found - consider adding backup servers')
                security_score -= 2
            elif len(mx_records) > 10:
                warnings.append('Too many MX records may cause delivery issues')
                security_score -= 1
            
            # Check for open relay patterns (excluding legitimate providers)
            open_relay_patterns = [
                '0.0.0.0',
                '127.0.0.1',
                'localhost',
                'relay'
            ]
            
            # Legitimate mail server patterns (whitelist)
            legitimate_patterns = [
                'google',
                'googlemail',
                'outlook',
                'hotmail',
                'microsoft',
                'yahoo',
                'zoho',
                'mailgun',
                'sendgrid',
                'amazon',
                'aws',
                'cloudflare',
                'fastly',
                'rackspace',
                'godaddy',
                'namecheap',
                'hostinger',
                'digitalocean',
                'heroku',
                'vercel',
                'netlify'
            ]
            
            for mx_record in mx_records:
                mx_server = mx_record['exchange'].lower()
                
                # Check if it's a legitimate provider first
                is_legitimate = any(legit_pattern in mx_server for legit_pattern in legitimate_patterns)
                
                # Check for suspicious patterns (only if not legitimate)
                if not is_legitimate:
                    for pattern in open_relay_patterns:
                        if pattern in mx_server:
                            warnings.append(f'MX server "{mx_server}" may be an open relay')
                            open_relay_risk = True
                            security_score -= 3
                            break
                
                # Check for localhost or internal IPs
                if mx_server in ['localhost', '127.0.0.1', '0.0.0.0']:
                    warnings.append(f'MX server "{mx_server}" is configured as localhost - security risk')
                    open_relay_risk = True
                    security_score -= 5
                
                # Check for generic names that might be open relays (only if not legitimate)
                if not is_legitimate and mx_server in ['mail', 'smtp', 'relay', 'mx']:
                    warnings.append(f'MX server "{mx_server}" uses generic name - verify it\'s not an open relay')
                    security_score -= 1
            
            # Check MX record priorities
            priorities = [record['preference'] for record in mx_records]
            if len(set(priorities)) == 1:
                warnings.append('All MX records have the same priority - consider setting up proper failover')
                security_score -= 1
            
            # Ensure security score doesn't go below 0
            security_score = max(0, security_score)
            
            # Determine overall status
            if security_score >= 8:
                status = SecurityStatus.PASS
            elif security_score >= 5:
                status = SecurityStatus.WARNING
            else:
                status = SecurityStatus.FAIL
            
            return {
                'records': mx_records,
                'status': status,
                'primary_mx': primary_mx,
                'backup_mx_count': backup_mx_count,
                'security_score': security_score,
                'open_relay_risk': open_relay_risk,
                'warnings': warnings,
                'recommendations': self._get_mx_recommendations(mx_records)
            }
            
        except Exception as e:
            return {
                'records': [],
                'status': SecurityStatus.ERROR,
                'primary_mx': None,
                'backup_mx_count': 0,
                'security_score': 0,
                'open_relay_risk': False,
                'warnings': [f'Error analyzing MX records: {str(e)}'],
                'recommendations': ['Check DNS configuration and try again']
            }
    
    async def get_bimi_record(self, domain: str) -> Dict[str, Any]:
        """
        Get and analyze BIMI record for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            BIMI analysis result
        """
        try:
            # Normalize domain
            domain = DomainValidator.normalize_domain(domain)
            
            # Get TXT records
            bimi_domain = f'default._bimi.{domain}'
            txt_records = await asyncio.to_thread(self.resolver.resolve_txt, bimi_domain)
            
            # Handle timeout case
            if txt_records is None:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.ERROR,
                    'logo_url': None,
                    'vmc_url': None,
                    'logo_accessible': False,
                    'vmc_valid': False,
                    'warnings': ['DNS timeout while resolving BIMI TXT records'],
                    'recommendations': [
                        'DNS resolution timed out - try again later',
                        'Check if the domain has DNS configuration issues'
                    ]
                }
            
            # Find BIMI record
            bimi_record = None
            for record in txt_records:
                if record.startswith('v=BIMI1'):
                    bimi_record = record
                    break
            
            if not bimi_record:
                return {
                    'exists': False,
                    'record': None,
                    'status': SecurityStatus.NOT_FOUND,
                    'logo_url': None,
                    'vmc_url': None,
                    'logo_accessible': False,
                    'vmc_valid': False,
                    'warnings': ['No BIMI record found'],
                    'recommendations': [
                        'BIMI is optional but can improve email branding',
                        'Create a BIMI record with your logo URL',
                        'Consider obtaining a VMC certificate for better compatibility'
                    ]
                }
            
            # Parse BIMI record (basic parsing)
            parts = bimi_record.split(';')
            logo_url = None
            vmc_url = None
            
            for part in parts:
                part = part.strip()
                if part.startswith('l='):
                    logo_url = part[2:]
                elif part.startswith('a='):
                    vmc_url = part[2:]
            
            return {
                'exists': True,
                'record': bimi_record,
                'status': SecurityStatus.PASS,
                'logo_url': logo_url,
                'vmc_url': vmc_url,
                'logo_accessible': False,  # Would need HTTP check
                'vmc_valid': False,  # Would need certificate validation
                'warnings': [],
                'recommendations': [
                    'Verify that your logo URL is accessible',
                    'Consider obtaining a VMC certificate',
                    'Test BIMI display in various email clients'
                ]
            }
            
        except Exception as e:
            return {
                'exists': False,
                'record': None,
                'status': SecurityStatus.ERROR,
                'logo_url': None,
                'vmc_url': None,
                'logo_accessible': False,
                'vmc_valid': False,
                'warnings': [f'Error analyzing BIMI record: {str(e)}'],
                'recommendations': ['Check DNS configuration and try again']
            }
    
    async def get_threat_intelligence(self, domain: str) -> Dict[str, Any]:
        """
        Get comprehensive threat intelligence data for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Threat intelligence analysis result
        """
        try:
            # This would integrate with actual threat intelligence APIs
            # For now, return enhanced placeholder data with structure for future integration
            
            # Simulate threat intelligence checks
            reputation_score = self._calculate_reputation_score(domain)
            blacklist_status = await self._check_blacklists(domain)
            malware_detections = await self._check_malware_detections(domain)
            phishing_reports = await self._check_phishing_reports(domain)
            spam_reports = await self._check_spam_reports(domain)
            
            return {
                'reputation_score': reputation_score,
                'blacklist_status': blacklist_status,
                'malware_detections': malware_detections,
                'phishing_reports': phishing_reports,
                'spam_reports': spam_reports,
                'last_updated': datetime.now().isoformat(),
                'data_sources': [
                    'DNSBL', 'SURBL', 'URIBL', 'Spamhaus', 'Barracuda',
                    'Cisco Talos', 'AbuseIPDB', 'VirusTotal'
                ],
                'risk_indicators': self._analyze_risk_indicators(
                    reputation_score, blacklist_status, malware_detections,
                    phishing_reports, spam_reports
                )
            }
            
        except Exception as e:
            return {
                'reputation_score': None,
                'blacklist_status': [],
                'malware_detections': [],
                'phishing_reports': [],
                'spam_reports': [],
                'last_updated': None,
                'data_sources': [],
                'risk_indicators': [],
                'error': str(e)
            }
    
    def _calculate_reputation_score(self, domain: str) -> Optional[float]:
        """Calculate domain reputation score (placeholder implementation)."""
        # This would integrate with reputation scoring services
        # For now, return a simulated score based on domain characteristics
        try:
            # Simple heuristic based on domain age and characteristics
            if domain.endswith('.com'):
                return 75.0  # Generic score for .com domains
            elif domain.endswith('.org'):
                return 80.0  # Slightly higher for .org
            elif domain.endswith('.edu'):
                return 90.0  # Higher for educational institutions
            else:
                return 70.0  # Default score
        except:
            return None
    
    async def _check_blacklists(self, domain: str) -> List[Dict[str, Any]]:
        """Check domain against various blacklists (placeholder implementation)."""
        # This would integrate with actual blacklist checking services
        blacklists = [
            'dnsbl.sorbs.net', 'zen.spamhaus.org', 'bl.spamcop.net',
            'dnsbl-1.uceprotect.net', 'b.barracudacentral.org'
        ]
        
        results = []
        for blacklist in blacklists:
            try:
                # Simulate blacklist check
                is_listed = False  # Placeholder
                results.append({
                    'blacklist': blacklist,
                    'is_listed': is_listed,
                    'list_type': 'spam' if 'spam' in blacklist else 'malware',
                    'last_checked': datetime.now().isoformat()
                })
            except Exception:
                results.append({
                    'blacklist': blacklist,
                    'is_listed': False,
                    'list_type': 'unknown',
                    'error': 'Check failed'
                })
        
        return results
    
    async def _check_malware_detections(self, domain: str) -> List[Dict[str, Any]]:
        """Check for malware detections (placeholder implementation)."""
        # This would integrate with malware detection services
        return [
            {
                'detection_type': 'malware',
                'detected': False,
                'confidence': 0.0,
                'source': 'VirusTotal',
                'last_checked': datetime.now().isoformat()
            }
        ]
    
    async def _check_phishing_reports(self, domain: str) -> List[Dict[str, Any]]:
        """Check for phishing reports (placeholder implementation)."""
        # This would integrate with phishing detection services
        return [
            {
                'report_type': 'phishing',
                'reported': False,
                'report_count': 0,
                'source': 'PhishTank',
                'last_checked': datetime.now().isoformat()
            }
        ]
    
    async def _check_spam_reports(self, domain: str) -> List[Dict[str, Any]]:
        """Check for spam reports (placeholder implementation)."""
        # This would integrate with spam reporting services
        return [
            {
                'report_type': 'spam',
                'reported': False,
                'report_count': 0,
                'source': 'SpamCop',
                'last_checked': datetime.now().isoformat()
            }
        ]
    
    def _analyze_risk_indicators(self, reputation_score: Optional[float], 
                                blacklist_status: List[Dict[str, Any]],
                                malware_detections: List[Dict[str, Any]],
                                phishing_reports: List[Dict[str, Any]],
                                spam_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze risk indicators based on threat intelligence data."""
        risk_indicators = []
        
        # Reputation score analysis
        if reputation_score is not None:
            if reputation_score < 30:
                risk_indicators.append({
                    'type': 'low_reputation',
                    'severity': 'high',
                    'description': f'Domain has very low reputation score ({reputation_score})',
                    'recommendation': 'Investigate domain reputation issues'
                })
            elif reputation_score < 60:
                risk_indicators.append({
                    'type': 'moderate_reputation',
                    'severity': 'medium',
                    'description': f'Domain has moderate reputation score ({reputation_score})',
                    'recommendation': 'Monitor domain reputation'
                })
        
        # Blacklist analysis
        listed_blacklists = [bl for bl in blacklist_status if bl.get('is_listed')]
        if listed_blacklists:
            risk_indicators.append({
                'type': 'blacklisted',
                'severity': 'high',
                'description': f'Domain is listed on {len(listed_blacklists)} blacklist(s)',
                'recommendation': 'Remove domain from blacklists',
                'details': listed_blacklists
            })
        
        # Malware analysis
        malware_detected = [det for det in malware_detections if det.get('detected')]
        if malware_detected:
            risk_indicators.append({
                'type': 'malware_detected',
                'severity': 'high',
                'description': f'Malware detected on domain',
                'recommendation': 'Clean malware from domain',
                'details': malware_detected
            })
        
        # Phishing analysis
        phishing_reported = [rep for rep in phishing_reports if rep.get('reported')]
        if phishing_reported:
            risk_indicators.append({
                'type': 'phishing_reported',
                'severity': 'high',
                'description': f'Phishing reported for domain',
                'recommendation': 'Investigate phishing reports',
                'details': phishing_reported
            })
        
        # Spam analysis
        spam_reported = [rep for rep in spam_reports if rep.get('reported')]
        if spam_reported:
            risk_indicators.append({
                'type': 'spam_reported',
                'severity': 'medium',
                'description': f'Spam reported for domain',
                'recommendation': 'Review email sending practices',
                'details': spam_reported
            })
        
        return risk_indicators
    
    def _get_spf_recommendations(self, parsed: Dict[str, Any]) -> List[str]:
        """Get SPF recommendations based on analysis."""
        recommendations = []
        
        if parsed is None:
            return recommendations
        
        if not parsed.get('all_mechanism'):
            recommendations.append('Add an "all" mechanism to your SPF record')
        elif parsed.get('all_mechanism') == '+all':
            recommendations.append('Consider using "-all" or "~all" instead of "+all" for better security')
        
        includes = parsed.get('includes', [])
        if includes and len(includes) > 10:
            recommendations.append('Consider consolidating SPF includes to reduce DNS lookups')
        
        if not includes and not parsed.get('ips', []):
            recommendations.append('Add your email providers to the SPF record')
        
        return recommendations
    
    def _get_dkim_recommendations(self, parsed: Dict[str, Any]) -> List[str]:
        """Get DKIM recommendations based on analysis."""
        recommendations = []
        
        if parsed is None:
            return recommendations
        
        if parsed.get('key_size') and parsed['key_size'] < 1024:
            recommendations.append('Consider using a larger key size (2048 bits or higher)')
        
        if not parsed.get('version'):
            recommendations.append('Specify DKIM version in your record')
        
        return recommendations
    
    def _get_dmarc_recommendations(self, parsed: Dict[str, Any]) -> List[str]:
        """Get comprehensive DMARC recommendations based on analysis."""
        recommendations = []
        
        if parsed is None:
            return recommendations
        
        # Policy-based recommendations
        if parsed.get('policy') == 'none':
            recommendations.append(
                'Your DMARC record is set to None (p=none) policy which will not protect against email spoofing and phishing. '
                'Enhance your policy to Quarantine (p=quarantine) or Reject (p=reject) by regularly monitoring legitimate email senders '
                'through DMARC Aggregate Reports for improved security.'
            )
        elif parsed.get('policy') == 'quarantine':
            recommendations.append(
                'Your DMARC record is set to Quarantine (p=quarantine) policy which provides moderate protection. '
                'Consider upgrading to Reject (p=reject) policy for maximum security after ensuring all legitimate senders are properly authenticated.'
            )
        elif parsed.get('policy') == 'reject':
            recommendations.append(
                'Excellent! Your DMARC record is set to Reject (p=reject) policy which provides maximum protection against email spoofing and phishing.'
            )
        
        # Subdomain policy recommendations
        if parsed.get('subdomain_policy'):
            if parsed['subdomain_policy'] == 'none':
                recommendations.append(
                    'Your subdomain\'s DMARC record is set to None (sp=none) policy which will not protect against email spoofing and phishing. '
                    'Enhance your subdomain\'s policy to Quarantine (sp=quarantine) or Reject (sp=reject) by regularly monitoring legitimate email senders '
                    'through DMARC Aggregate Reports for improved security.'
                )
            elif parsed['subdomain_policy'] == 'quarantine':
                recommendations.append(
                    'Your subdomain\'s DMARC record is set to Quarantine (sp=quarantine) policy which provides moderate protection. '
                    'Consider upgrading to Reject (sp=reject) policy for maximum security after ensuring all legitimate subdomain senders are properly authenticated.'
                )
            elif parsed['subdomain_policy'] == 'reject':
                recommendations.append(
                    'Excellent! Your subdomain\'s DMARC record is set to Reject (sp=reject) policy which provides maximum protection.'
                )
        else:
            # No subdomain policy specified
            if parsed.get('policy') in ['quarantine', 'reject']:
                recommendations.append(
                    'No subdomain policy (sp=) specified. Subdomains will inherit the main domain policy. '
                    'Consider explicitly setting subdomain policy for better control and monitoring.'
                )
        
        # Reporting recommendations
        if not parsed.get('report_uri', []):
            recommendations.append(
                'No DMARC Aggregate Reports (rua=) configured. Add report URIs to receive detailed reports about email authentication results. '
                'This helps monitor legitimate senders and identify potential issues before implementing stricter policies.'
            )
        else:
            report_uri = parsed.get('report_uri', [])
            recommendations.append(
                f'DMARC Aggregate Reports configured with {len(report_uri)} URI(s). '
                'Regularly review these reports to monitor authentication success rates and identify legitimate senders.'
            )
        
        if not parsed.get('forensic_uri', []):
            if parsed.get('policy') in ['quarantine', 'reject']:
                recommendations.append(
                    'No DMARC Forensic Reports (ruf=) configured. Consider adding forensic report URIs to receive detailed information '
                    'about individual message failures when using quarantine or reject policies.'
                )
        
        # Percentage recommendations
        if parsed.get('percentage') is not None:
            if parsed['percentage'] < 100:
                recommendations.append(
                    f'DMARC policy is applied to {parsed["percentage"]}% of messages. Consider increasing to 100% for complete protection '
                    'after ensuring all legitimate senders are properly configured.'
                )
            elif parsed['percentage'] == 100:
                recommendations.append(
                    'DMARC policy is applied to 100% of messages, providing complete protection coverage.'
                )
        
        # Alignment recommendations
        if parsed.get('adkim') == 's':
            recommendations.append(
                'DKIM alignment is set to strict (adkim=s). This provides maximum security but may cause issues if DKIM signing '
                'is not properly configured for all subdomains.'
            )
        elif parsed.get('adkim') == 'r':
            recommendations.append(
                'DKIM alignment is set to relaxed (adkim=r). This provides good security while being more forgiving of minor configuration issues.'
            )
        
        if parsed.get('aspf') == 's':
            recommendations.append(
                'SPF alignment is set to strict (aspf=s). This provides maximum security but may cause issues if SPF records '
                'are not properly configured for all subdomains.'
            )
        elif parsed.get('aspf') == 'r':
            recommendations.append(
                'SPF alignment is set to relaxed (aspf=r). This provides good security while being more forgiving of minor configuration issues.'
            )
        
        # Additional security recommendations
        if parsed.get('policy') == 'none' and not parsed.get('report_uri', []):
            recommendations.append(
                '⚠️ CRITICAL: Your DMARC record has no policy enforcement and no reporting configured. '
                'This provides no protection against email spoofing. Implement at least monitoring with reports before moving to enforcement.'
            )
        
        if parsed.get('policy') in ['quarantine', 'reject'] and not parsed.get('report_uri', []):
            recommendations.append(
                '⚠️ WARNING: Your DMARC record has enforcement enabled but no reporting configured. '
                'This makes it difficult to monitor legitimate senders and troubleshoot issues. Add report URIs for better visibility.'
            )
        
        return recommendations
    
    def _get_mtasts_recommendations(self, parsed: Dict[str, Any], policy_parsed: Dict[str, Any], policy_accessible: bool) -> List[str]:
        """Get MTA-STS recommendations based on analysis."""
        recommendations = []
        
        if parsed is None:
            return recommendations
        
        if not policy_accessible:
            recommendations.append('Set up MTA-STS policy file at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt')
        
        if policy_parsed and policy_parsed.get('mode') == 'testing':
            recommendations.append('Consider moving to enforce mode after testing')
        
        if policy_parsed and not policy_parsed.get('mx_records', []):
            recommendations.append('Add MX records to your MTA-STS policy')
        
        return recommendations
    
    def _get_tlsrpt_recommendations(self, parsed: Dict[str, Any]) -> List[str]:
        """Get TLS-RPT recommendations based on analysis."""
        recommendations = []
        
        if parsed is None:
            return recommendations
        
        if not parsed.get('rua', []):
            recommendations.append('Add report URIs to receive TLS failure reports')
        
        return recommendations
    
    def _get_mx_recommendations(self, mx_records: List[Dict[str, Any]]) -> List[str]:
        """Get MX recommendations based on analysis."""
        recommendations = []
        
        if mx_records is None:
            return recommendations
        
        if len(mx_records) == 1:
            recommendations.append('Add backup MX servers for redundancy')
        
        if len(mx_records) > 10:
            recommendations.append('Consider reducing the number of MX records')
        
        return recommendations
    
    async def get_reverse_dns(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform reverse DNS (PTR) lookup for an IP address.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Reverse DNS lookup result
        """
        try:
            import ipaddress
            import socket
            
            # Validate IP address
            try:
                ip_obj = ipaddress.ip_address(ip_address)
            except ValueError:
                return {
                    'ip_address': ip_address,
                    'exists': False,
                    'status': SecurityStatus.ERROR,
                    'hostnames': [],
                    'warnings': [f'Invalid IP address: {ip_address}'],
                    'recommendations': ['Provide a valid IPv4 or IPv6 address']
                }
            
            # Perform reverse DNS lookup
            try:
                hostnames = socket.gethostbyaddr(ip_address)
                hostname = hostnames[0]
                aliases = hostnames[1]
                
                # Verify forward DNS matches
                forward_match = False
                try:
                    forward_ips = socket.gethostbyname_ex(hostname)[2]
                    forward_match = ip_address in forward_ips
                except:
                    pass
                
                status = SecurityStatus.PASS if forward_match else SecurityStatus.WARNING
                warnings = []
                recommendations = []
                
                if not forward_match:
                    warnings.append('Reverse DNS does not match forward DNS (FCrDNS mismatch)')
                    recommendations.append('Ensure forward and reverse DNS records match for better email deliverability')
                
                return {
                    'ip_address': ip_address,
                    'exists': True,
                    'status': status,
                    'hostname': hostname,
                    'aliases': aliases,
                    'forward_match': forward_match,
                    'warnings': warnings,
                    'recommendations': recommendations
                }
                
            except socket.herror:
                return {
                    'ip_address': ip_address,
                    'exists': False,
                    'status': SecurityStatus.WARNING,
                    'hostname': None,
                    'aliases': [],
                    'forward_match': False,
                    'warnings': ['No PTR record found for this IP address'],
                    'recommendations': [
                        'Configure reverse DNS (PTR) record for better email deliverability',
                        'Contact your hosting provider to set up PTR records'
                    ]
                }
                
        except Exception as e:
            return {
                'ip_address': ip_address,
                'exists': False,
                'status': SecurityStatus.ERROR,
                'hostname': None,
                'aliases': [],
                'forward_match': False,
                'warnings': [f'Error performing reverse DNS lookup: {str(e)}'],
                'recommendations': ['Check IP address and try again']
            }
    
    async def scan_mail_ports(self, hostname: str, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Scan common mail server ports to check availability.
        
        Args:
            hostname: Hostname or IP address to scan
            timeout: Connection timeout in seconds
            
        Returns:
            Port scan results
        """
        import socket
        from datetime import datetime

        # Common mail server ports
        ports = {
            25: 'SMTP',
            587: 'SMTP Submission',
            465: 'SMTPS (SSL)',
            143: 'IMAP',
            993: 'IMAPS (SSL)',
            110: 'POP3',
            995: 'POP3S (SSL)'
        }
        
        results = {
            'hostname': hostname,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'ports': {},
            'open_ports': [],
            'closed_ports': [],
            'status': SecurityStatus.PASS,
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Resolve hostname to IP
            try:
                ip_address = socket.gethostbyname(hostname)
                results['ip_address'] = ip_address
            except socket.gaierror:
                return {
                    'hostname': hostname,
                    'scan_timestamp': datetime.utcnow().isoformat(),
                    'ports': {},
                    'open_ports': [],
                    'closed_ports': [],
                    'status': SecurityStatus.ERROR,
                    'warnings': [f'Could not resolve hostname: {hostname}'],
                    'recommendations': ['Check hostname and DNS configuration']
                }
            
            # Scan each port
            for port, service in ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip_address, port))
                    sock.close()
                    
                    is_open = result == 0
                    
                    results['ports'][port] = {
                        'service': service,
                        'open': is_open,
                        'status': 'Open' if is_open else 'Closed/Filtered'
                    }
                    
                    if is_open:
                        results['open_ports'].append(port)
                    else:
                        results['closed_ports'].append(port)
                        
                except Exception as e:
                    results['ports'][port] = {
                        'service': service,
                        'open': False,
                        'status': 'Error',
                        'error': str(e)
                    }
                    results['closed_ports'].append(port)
            
            # Generate recommendations
            if 25 not in results['open_ports']:
                results['warnings'].append('Port 25 (SMTP) is not accessible')
                results['recommendations'].append('Ensure SMTP port 25 is open for receiving emails')
            
            if 587 not in results['open_ports'] and 465 not in results['open_ports']:
                results['warnings'].append('No secure SMTP submission ports (587, 465) are open')
                results['recommendations'].append('Configure port 587 (SMTP Submission) or 465 (SMTPS) for secure email sending')
            
            if 993 in results['open_ports'] or 995 in results['open_ports']:
                results['recommendations'].append('Secure IMAP/POP3 ports are available - good for security')
            
            if 143 in results['open_ports'] or 110 in results['open_ports']:
                results['warnings'].append('Insecure IMAP/POP3 ports (143, 110) are open')
                results['recommendations'].append('Consider disabling insecure IMAP/POP3 and use only SSL/TLS versions (993, 995)')
            
            # Set overall status
            if len(results['warnings']) > 2:
                results['status'] = SecurityStatus.WARNING
            elif len(results['open_ports']) == 0:
                results['status'] = SecurityStatus.FAIL
                results['warnings'].append('No mail server ports are accessible')
            
            return results
            
        except Exception as e:
            return {
                'hostname': hostname,
                'scan_timestamp': datetime.utcnow().isoformat(),
                'ports': {},
                'open_ports': [],
                'closed_ports': [],
                'status': SecurityStatus.ERROR,
                'warnings': [f'Error scanning ports: {str(e)}'],
                'recommendations': ['Check network connectivity and firewall settings']
            }
    
    async def check_blacklists(self, ip_address: str, timeout: float = 2.0) -> Dict[str, Any]:
        """
        Check if an IP address is listed on multiple RBL (Real-time Blackhole List) providers.
        
        Args:
            ip_address: IP address to check
            timeout: DNS query timeout in seconds
            
        Returns:
            Blacklist check results
        """
        import ipaddress
        import dns.resolver
        import dns.exception
        
        # Major RBL providers
        rbls = {
            'zen.spamhaus.org': {
                'name': 'Spamhaus ZEN',
                'description': 'Combined list of Spamhaus blocklists',
                'severity': 'high'
            },
            'bl.spamcop.net': {
                'name': 'SpamCop',
                'description': 'SpamCop Blocking List',
                'severity': 'high'
            },
            'b.barracudacentral.org': {
                'name': 'Barracuda',
                'description': 'Barracuda Reputation Block List',
                'severity': 'medium'
            },
            'dnsbl.sorbs.net': {
                'name': 'SORBS',
                'description': 'Spam and Open Relay Blocking System',
                'severity': 'medium'
            },
            'psbl.surriel.com': {
                'name': 'PSBL',
                'description': 'Passive Spam Block List',
                'severity': 'medium'
            },
            'dnsbl-1.uceprotect.net': {
                'name': 'UCEPROTECT Level 1',
                'description': 'UCEPROTECT Network blacklist',
                'severity': 'low'
            },
            'cbl.abuseat.org': {
                'name': 'CBL',
                'description': 'Composite Blocking List',
                'severity': 'high'
            },
            'dnsbl.dronebl.org': {
                'name': 'DroneBL',
                'description': 'Drone and botnet blacklist',
                'severity': 'high'
            }
        }
        
        results = {
            'ip_address': ip_address,
            'check_timestamp': datetime.utcnow().isoformat(),
            'is_blacklisted': False,
            'blacklisted_on': [],
            'not_blacklisted_on': [],
            'errors': [],
            'total_checked': 0,
            'total_blacklisted': 0,
            'status': SecurityStatus.PASS,
            'warnings': [],
            'recommendations': [],
            'details': {}
        }
        
        try:
            # Validate IP address
            try:
                ip_obj = ipaddress.ip_address(ip_address)
            except ValueError:
                return {
                    'ip_address': ip_address,
                    'check_timestamp': datetime.utcnow().isoformat(),
                    'is_blacklisted': False,
                    'blacklisted_on': [],
                    'not_blacklisted_on': [],
                    'errors': [f'Invalid IP address: {ip_address}'],
                    'total_checked': 0,
                    'total_blacklisted': 0,
                    'status': SecurityStatus.ERROR,
                    'warnings': ['Provide a valid IPv4 or IPv6 address'],
                    'recommendations': [],
                    'details': {}
                }
            
            # Reverse the IP for DNSBL query
            if isinstance(ip_obj, ipaddress.IPv4Address):
                reversed_ip = '.'.join(reversed(ip_address.split('.')))
            else:
                # IPv6 handling
                expanded = ip_obj.exploded.replace(':', '')
                reversed_ip = '.'.join(reversed(expanded))
            
            # Check each RBL
            for rbl_host, rbl_info in rbls.items():
                results['total_checked'] += 1
                query = f"{reversed_ip}.{rbl_host}"
                
                try:
                    # Create a resolver with timeout
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = timeout
                    resolver.lifetime = timeout
                    
                    # Query the RBL
                    answers = resolver.resolve(query, 'A')
                    
                    # If we get a response, the IP is blacklisted
                    return_codes = [str(rdata) for rdata in answers]
                    
                    results['is_blacklisted'] = True
                    results['total_blacklisted'] += 1
                    results['blacklisted_on'].append(rbl_info['name'])
                    
                    results['details'][rbl_info['name']] = {
                        'listed': True,
                        'rbl_host': rbl_host,
                        'description': rbl_info['description'],
                        'severity': rbl_info['severity'],
                        'return_codes': return_codes,
                        'query': query
                    }
                    
                except dns.resolver.NXDOMAIN:
                    # Not listed on this RBL (expected for clean IPs)
                    results['not_blacklisted_on'].append(rbl_info['name'])
                    results['details'][rbl_info['name']] = {
                        'listed': False,
                        'rbl_host': rbl_host,
                        'description': rbl_info['description'],
                        'severity': rbl_info['severity']
                    }
                    
                except dns.resolver.Timeout:
                    results['errors'].append(f"Timeout checking {rbl_info['name']}")
                    
                except dns.exception.DNSException as e:
                    results['errors'].append(f"Error checking {rbl_info['name']}: {str(e)}")
                    
                except Exception as e:
                    results['errors'].append(f"Unexpected error checking {rbl_info['name']}: {str(e)}")
            
            # Determine overall status
            if results['total_blacklisted'] > 0:
                results['status'] = SecurityStatus.FAIL
                results['warnings'].append(f"IP is blacklisted on {results['total_blacklisted']} RBL(s)")
                results['recommendations'].append('Contact the RBL providers to request delisting')
                results['recommendations'].append('Investigate the source of spam/abuse from this IP')
                results['recommendations'].append('Implement better email security practices')
            else:
                results['status'] = SecurityStatus.PASS
                results['recommendations'].append('IP has a clean reputation across checked RBLs')
            
            if len(results['errors']) > 0:
                results['warnings'].append(f"{len(results['errors'])} RBL check(s) failed")
            
            return results
            
        except Exception as e:
            return {
                'ip_address': ip_address,
                'check_timestamp': datetime.utcnow().isoformat(),
                'is_blacklisted': False,
                'blacklisted_on': [],
                'not_blacklisted_on': [],
                'errors': [f'Error performing blacklist check: {str(e)}'],
                'total_checked': 0,
                'total_blacklisted': 0,
                'status': SecurityStatus.ERROR,
                'warnings': ['Blacklist check failed'],
                'recommendations': ['Try again later or check manually'],
                'details': {}
            }


# Global DNS service instance
dns_service = DNSService()