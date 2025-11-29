import asyncio
import aiohttp
import socket
import dns.resolver
from typing import Dict, List, Any, Optional
from datetime import datetime
import re


class BlacklistService:
    """Service for checking domain reputation across multiple blacklists."""
    
    def __init__(self):
        self.timeout = 10
        # Configuration for handling false positives
        self.ignore_false_positives = True  # Set to False to include all listings
        self.blacklists = {
            # Major DNS-based blacklists
            'spamhaus_zen': {
                'name': 'Spamhaus ZEN',
                'description': 'Spamhaus ZEN (Spam and Open Relay Blocking List)',
                'dns_zone': 'zen.spamhaus.org',
                'severity': 'high',
                'category': 'spam'
            },
            'spamhaus_sbl': {
                'name': 'Spamhaus SBL',
                'description': 'Spamhaus SBL (Spamhaus Block List)',
                'dns_zone': 'sbl.spamhaus.org',
                'severity': 'high',
                'category': 'spam'
            },
            'spamhaus_xbl': {
                'name': 'Spamhaus XBL',
                'description': 'Spamhaus XBL (Exploits Block List)',
                'dns_zone': 'xbl.spamhaus.org',
                'severity': 'high',
                'category': 'exploits'
            },
            'spamhaus_pbl': {
                'name': 'Spamhaus PBL',
                'description': 'Spamhaus PBL (Policy Block List)',
                'dns_zone': 'pbl.spamhaus.org',
                'severity': 'medium',
                'category': 'policy'
            },
            
            # SORBS family of blacklists
            'sorbs_dnsbl': {
                'name': 'SORBS DNSBL',
                'description': 'SORBS DNS Blacklist',
                'dns_zone': 'dnsbl.sorbs.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'sorbs_http': {
                'name': 'SORBS HTTP',
                'description': 'SORBS HTTP Blacklist',
                'dns_zone': 'http.dnsbl.sorbs.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'sorbs_smtp': {
                'name': 'SORBS SMTP',
                'description': 'SORBS SMTP Blacklist',
                'dns_zone': 'smtp.dnsbl.sorbs.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'sorbs_socks': {
                'name': 'SORBS SOCKS',
                'description': 'SORBS SOCKS Proxy Blacklist',
                'dns_zone': 'socks.dnsbl.sorbs.net',
                'severity': 'medium',
                'category': 'proxy'
            },
            'sorbs_misc': {
                'name': 'SORBS Misc',
                'description': 'SORBS Miscellaneous Blacklist',
                'dns_zone': 'misc.dnsbl.sorbs.net',
                'severity': 'low',
                'category': 'spam'
            },
            'sorbs_web': {
                'name': 'SORBS Web',
                'description': 'SORBS Web Blacklist',
                'dns_zone': 'web.dnsbl.sorbs.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'sorbs_zombie': {
                'name': 'SORBS Zombie',
                'description': 'SORBS Zombie DNS Blacklist',
                'dns_zone': 'zombie.dnsbl.sorbs.net',
                'severity': 'high',
                'category': 'malware'
            },
            'sorbs_dul': {
                'name': 'SORBS DUL',
                'description': 'SORBS Dynamic User List',
                'dns_zone': 'dul.dnsbl.sorbs.net',
                'severity': 'medium',
                'category': 'policy'
            },
            'sorbs_spam': {
                'name': 'SORBS Spam',
                'description': 'SORBS Spam Blacklist',
                'dns_zone': 'spam.dnsbl.sorbs.net',
                'severity': 'medium',
                'category': 'spam'
            },
            
            # Commercial and reputation blacklists
            'barracuda': {
                'name': 'Barracuda',
                'description': 'Barracuda Reputation Block List',
                'dns_zone': 'b.barracudacentral.org',
                'severity': 'medium',
                'category': 'reputation'
            },
            'spamcop': {
                'name': 'SpamCop',
                'description': 'SpamCop Blocking List',
                'dns_zone': 'bl.spamcop.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'uribl': {
                'name': 'URI Blacklist',
                'description': 'URI Blacklist',
                'dns_zone': 'black.uribl.com',
                'severity': 'medium',
                'category': 'reputation'
            },
            
            # Abuse and security blacklists
            'abuseat': {
                'name': 'AbuseAt',
                'description': 'AbuseAt DNS Blacklist',
                'dns_zone': 'cbl.abuseat.org',
                'severity': 'medium',
                'category': 'abuse'
            },
            'combined_abuse': {
                'name': 'Combined Abuse',
                'description': 'Combined Abuse.ch Blacklist',
                'dns_zone': 'combined.abuse.ch',
                'severity': 'high',
                'category': 'malware'
            },
            'drone_abuse': {
                'name': 'Drone Abuse',
                'description': 'Drone Abuse.ch Blacklist',
                'dns_zone': 'drone.abuse.ch',
                'severity': 'high',
                'category': 'malware'
            },
            'spam_abuse': {
                'name': 'Spam Abuse',
                'description': 'Spam Abuse.ch Blacklist',
                'dns_zone': 'spam.abuse.ch',
                'severity': 'medium',
                'category': 'spam'
            },
            
            # Regional and specialized blacklists
            'cdl_antispam': {
                'name': 'CDL Anti-Spam',
                'description': 'CDL Anti-Spam Organization China',
                'dns_zone': 'cdl.anti-spam.org.cn',
                'severity': 'medium',
                'category': 'spam'
            },
            'korea_services': {
                'name': 'Korea Services',
                'description': 'Korea Services Network',
                'dns_zone': 'korea.services.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'rbl_jp': {
                'name': 'RBL Japan',
                'description': 'RBL Japan Short Blacklist',
                'dns_zone': 'short.rbl.jp',
                'severity': 'medium',
                'category': 'spam'
            },
            'virus_rbl_jp': {
                'name': 'Virus RBL Japan',
                'description': 'Virus RBL Japan',
                'dns_zone': 'virus.rbl.jp',
                'severity': 'high',
                'category': 'malware'
            },
            'singular_ttk': {
                'name': 'Singular TTK',
                'description': 'Singular TTK PTE Hungary',
                'dns_zone': 'singular.ttk.pte.hu',
                'severity': 'medium',
                'category': 'spam'
            },
            
            # Proxy and network blacklists
            'proxy_bl_gweep': {
                'name': 'Proxy BL Gweep',
                'description': 'Proxy Blacklist Gweep',
                'dns_zone': 'proxy.bl.gweep.ca',
                'severity': 'medium',
                'category': 'proxy'
            },
            'relays_bl_gweep': {
                'name': 'Relays BL Gweep',
                'description': 'Relays Blacklist Gweep',
                'dns_zone': 'relays.bl.gweep.ca',
                'severity': 'medium',
                'category': 'relay'
            },
            'relays_nether': {
                'name': 'Relays Nether',
                'description': 'Relays Nether Network',
                'dns_zone': 'relays.nether.net',
                'severity': 'medium',
                'category': 'relay'
            },
            
            # Additional spam and reputation blacklists
            'all_s5h': {
                'name': 'All S5H',
                'description': 'All S5H Network',
                'dns_zone': 'all.s5h.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'blacklist_woody': {
                'name': 'Blacklist Woody',
                'description': 'Blacklist Woody.ch',
                'dns_zone': 'blacklist.woody.ch',
                'severity': 'medium',
                'category': 'spam'
            },
            'bogons_cymru': {
                'name': 'Bogons Cymru',
                'description': 'Bogons Cymru',
                'dns_zone': 'bogons.cymru.com',
                'severity': 'medium',
                'category': 'bogon'
            },
            'db_wpbl': {
                'name': 'DB WPBL',
                'description': 'DB WPBL Info',
                'dns_zone': 'db.wpbl.info',
                'severity': 'medium',
                'category': 'spam'
            },
            'uceprotect_1': {
                'name': 'UCEProtect Level 1',
                'description': 'UCEProtect Level 1',
                'dns_zone': 'dnsbl-1.uceprotect.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'uceprotect_2': {
                'name': 'UCEProtect Level 2',
                'description': 'UCEProtect Level 2',
                'dns_zone': 'dnsbl-2.uceprotect.net',
                'severity': 'high',
                'category': 'spam'
            },
            'uceprotect_3': {
                'name': 'UCEProtect Level 3',
                'description': 'UCEProtect Level 3',
                'dns_zone': 'dnsbl-3.uceprotect.net',
                'severity': 'high',
                'category': 'spam'
            },
            'anticaptcha': {
                'name': 'AntiCaptcha',
                'description': 'AntiCaptcha DNS Blacklist',
                'dns_zone': 'dnsbl.anticaptcha.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'dronebl': {
                'name': 'DroneBL',
                'description': 'DroneBL DNS Blacklist',
                'dns_zone': 'dnsbl.dronebl.org',
                'severity': 'high',
                'category': 'malware'
            },
            'inps_de': {
                'name': 'INPS DE',
                'description': 'INPS Germany DNS Blacklist',
                'dns_zone': 'dnsbl.inps.de',
                'severity': 'medium',
                'category': 'spam'
            },
            'spfbl': {
                'name': 'SPFBL',
                'description': 'SPFBL DNS Blacklist',
                'dns_zone': 'dnsbl.spfbl.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'duinv_aupads': {
                'name': 'DUINV AUPADS',
                'description': 'DUINV AUPADS',
                'dns_zone': 'duinv.aupads.org',
                'severity': 'medium',
                'category': 'spam'
            },
            'dyna_spamrats': {
                'name': 'Dyna SpamRats',
                'description': 'Dyna SpamRats',
                'dns_zone': 'dyna.spamrats.com',
                'severity': 'medium',
                'category': 'spam'
            },
            'dynip_rothen': {
                'name': 'DynIP Rothen',
                'description': 'DynIP Rothen',
                'dns_zone': 'dynip.rothen.com',
                'severity': 'medium',
                'category': 'spam'
            },
            'backscatterer': {
                'name': 'Backscatterer',
                'description': 'Backscatterer IPS',
                'dns_zone': 'ips.backscatterer.org',
                'severity': 'medium',
                'category': 'backscatter'
            },
            'manitu': {
                'name': 'Manitu',
                'description': 'Manitu DNS Blacklist',
                'dns_zone': 'ix.dnsbl.manitu.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'noptr_spamrats': {
                'name': 'NOPTR SpamRats',
                'description': 'NOPTR SpamRats',
                'dns_zone': 'noptr.spamrats.com',
                'severity': 'medium',
                'category': 'spam'
            },
            'orvedb_aupads': {
                'name': 'Orvedb AUPADS',
                'description': 'Orvedb AUPADS',
                'dns_zone': 'orvedb.aupads.org',
                'severity': 'medium',
                'category': 'spam'
            },
            'psbl_surriel': {
                'name': 'PSBL Surriel',
                'description': 'PSBL Surriel',
                'dns_zone': 'psbl.surriel.com',
                'severity': 'medium',
                'category': 'spam'
            },
            'spamrats': {
                'name': 'SpamRats',
                'description': 'SpamRats',
                'dns_zone': 'spam.spamrats.com',
                'severity': 'medium',
                'category': 'spam'
            },
            'spambot_digibase': {
                'name': 'SpamBot Digibase',
                'description': 'SpamBot BLS Digibase',
                'dns_zone': 'spambot.bls.digibase.ca',
                'severity': 'medium',
                'category': 'spam'
            },
            'spamrbl_imp': {
                'name': 'SpamRBL IMP',
                'description': 'SpamRBL IMP',
                'dns_zone': 'spamrbl.imp.ch',
                'severity': 'medium',
                'category': 'spam'
            },
            'spamsources_fabel': {
                'name': 'SpamSources Fabel',
                'description': 'SpamSources Fabel',
                'dns_zone': 'spamsources.fabel.dk',
                'severity': 'medium',
                'category': 'spam'
            },
            'ubl_lashback': {
                'name': 'UBL Lashback',
                'description': 'UBL Lashback',
                'dns_zone': 'ubl.lashback.com',
                'severity': 'medium',
                'category': 'spam'
            },
            'ubl_unsubscore': {
                'name': 'UBL Unsubscore',
                'description': 'UBL Unsubscore',
                'dns_zone': 'ubl.unsubscore.com',
                'severity': 'medium',
                'category': 'spam'
            },
            'wormrbl_imp': {
                'name': 'WormRBL IMP',
                'description': 'WormRBL IMP',
                'dns_zone': 'wormrbl.imp.ch',
                'severity': 'high',
                'category': 'malware'
            },
            'mailspike': {
                'name': 'MailSpike',
                'description': 'MailSpike Z Blacklist',
                'dns_zone': 'z.mailspike.net',
                'severity': 'medium',
                'category': 'spam'
            },
            'anonmails': {
                'name': 'AnonMails',
                'description': 'AnonMails DNS Blacklist',
                'dns_zone': 'spam.dnsbl.anonmails.de',
                'severity': 'medium',
                'category': 'spam'
            }
        }
    
    async def check_domain_blacklists(self, domain: str) -> Dict[str, Any]:
        """
        Check domain against multiple blacklists.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Comprehensive blacklist analysis result
        """
        try:
            # Get all domain IP addresses
            ip_addresses = self._resolve_domain_ips(domain)
            if not ip_addresses:
                return {
                    'domain': domain,
                    'ip_address': None,
                    'ip_addresses': [],
                    'blacklisted': False,
                    'blacklist_count': 0,
                    'reputation_score': 100,
                    'risk_level': 'unknown',
                    'blacklists': [],
                    'summary': 'Could not resolve domain IP address',
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Use the first IP for backward compatibility
            ip_address = ip_addresses[0]
            
            # Check against all blacklists
            blacklist_results = []
            blacklisted_count = 0
            
            for bl_key, bl_config in self.blacklists.items():
                result = self._check_single_blacklist(domain, ip_address, bl_key, bl_config)
                blacklist_results.append(result)
                
                if result['listed']:
                    blacklisted_count += 1
            
            # Calculate reputation score
            reputation_score = self._calculate_reputation_score(blacklist_results)
            risk_level = self._determine_risk_level(reputation_score, blacklisted_count)
            
            # Generate summary
            summary = self._generate_summary(blacklist_results, blacklisted_count)
            
            return {
                'domain': domain,
                'ip_address': ip_address,
                'ip_addresses': ip_addresses,
                'blacklisted': blacklisted_count > 0,
                'blacklist_count': blacklisted_count,
                'reputation_score': reputation_score,
                'risk_level': risk_level,
                'blacklists': blacklist_results,
                'summary': summary,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'domain': domain,
                'ip_address': None,
                'ip_addresses': [],
                'blacklisted': False,
                'blacklist_count': 0,
                'reputation_score': 0,
                'risk_level': 'error',
                'blacklists': [],
                'summary': f'Error checking blacklists: {str(e)}',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _resolve_domain_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            # Try A record first
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, 'A')
            if answers:
                # Return the first IP address (primary)
                return str(answers[0])
            
            return None
        except Exception as e:
            print(f"Error resolving IP for {domain}: {str(e)}")
            return None
    
    def _resolve_domain_ips(self, domain: str) -> List[str]:
        """Resolve domain to all IP addresses."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except Exception as e:
            print(f"Error resolving IPs for {domain}: {str(e)}")
            return []
    
    def _check_single_blacklist(self, domain: str, ip_address: str, bl_key: str, bl_config: Dict[str, Any]) -> Dict[str, Any]:
        """Check domain against a single blacklist."""
        try:
            # Reverse IP for DNS lookup
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
            lookup_domain = f"{reversed_ip}.{bl_config['dns_zone']}"
            
            # Perform DNS lookup
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(lookup_domain, 'A')
                # If we get a response, the IP is listed
                response_ip = str(answers[0])
                
                # Check for specific response codes that indicate listing
                # Some blacklists return 127.0.0.x where x indicates the reason
                is_listed = True
                
                # SPFBL specific response code interpretation
                if bl_key == 'spfbl':
                    # SPFBL response codes:
                    # 127.0.0.1 - Listed for spam
                    # 127.0.0.2 - Listed for phishing
                    # 127.0.0.3 - Listed for malware
                    # 127.0.0.4 - Listed for other reasons (often false positives)
                    # 127.0.0.5 - Listed for policy violation
                    if response_ip == '127.0.0.4':
                        # This is often a false positive - listed for "other reasons"
                        if self.ignore_false_positives:
                            is_listed = False  # Treat as not listed due to false positive
                            bl_config['description'] += ' (Response 127.0.0.4 ignored as potential false positive)'
                        else:
                            is_listed = True
                            bl_config['description'] += ' (Response 127.0.0.4 - may be false positive)'
                    elif response_ip == '127.0.0.5':
                        # Policy violation - still listed but less severe
                        is_listed = True
                    elif response_ip in ['127.0.0.1', '127.0.0.2', '127.0.0.3']:
                        # These are more serious listings
                        is_listed = True
                        bl_config['severity'] = 'high'  # Upgrade severity for serious listings
                
                # AHBL specific handling - 127.0.0.5 might be a false positive
                if bl_key == 'dnsbl_ahbl' and response_ip == '127.0.0.5':
                    is_listed = False  # Treat as not listed due to potential false positives
                
                return {
                    'blacklist': bl_key,
                    'name': bl_config['name'],
                    'description': bl_config['description'],
                    'listed': is_listed,
                    'response': response_ip,
                    'severity': bl_config['severity'],
                    'category': bl_config['category'],
                    'lookup_domain': lookup_domain,
                    'error': None
                }
                
            except dns.resolver.NXDOMAIN:
                # Not listed
                return {
                    'blacklist': bl_key,
                    'name': bl_config['name'],
                    'description': bl_config['description'],
                    'listed': False,
                    'response': None,
                    'severity': bl_config['severity'],
                    'category': bl_config['category'],
                    'lookup_domain': lookup_domain,
                    'error': None
                }
                
            except Exception as e:
                # Error checking this blacklist
                return {
                    'blacklist': bl_key,
                    'name': bl_config['name'],
                    'description': bl_config['description'],
                    'listed': False,
                    'response': None,
                    'severity': bl_config['severity'],
                    'category': bl_config['category'],
                    'lookup_domain': lookup_domain,
                    'error': str(e)
                }
                
        except Exception as e:
            return {
                'blacklist': bl_key,
                'name': bl_config['name'],
                'description': bl_config['description'],
                'listed': False,
                'response': None,
                'severity': bl_config['severity'],
                'category': bl_config['category'],
                'lookup_domain': None,
                'error': str(e)
            }
    
    def _calculate_reputation_score(self, blacklist_results: List[Dict[str, Any]]) -> int:
        """Calculate reputation score based on blacklist results."""
        if not blacklist_results:
            return 100
        
        total_checks = len(blacklist_results)
        successful_checks = len([r for r in blacklist_results if r['error'] is None])
        
        if successful_checks == 0:
            return 0
        
        # Calculate score based on listings
        listed_count = len([r for r in blacklist_results if r['listed']])
        
        # Base score starts at 100
        score = 100
        
        # Deduct points for each listing (weighted by severity)
        for result in blacklist_results:
            if result['listed']:
                if result['severity'] == 'high':
                    score -= 20
                elif result['severity'] == 'medium':
                    score -= 10
                elif result['severity'] == 'low':
                    score -= 5
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Adjust for successful check ratio
        if successful_checks < total_checks:
            score = int(score * (successful_checks / total_checks))
        
        return score
    
    def _determine_risk_level(self, reputation_score: int, blacklisted_count: int) -> str:
        """Determine risk level based on reputation score and blacklist count."""
        if blacklisted_count == 0:
            return 'low'
        elif reputation_score >= 80:
            return 'low'
        elif reputation_score >= 60:
            return 'medium'
        elif reputation_score >= 40:
            return 'high'
        else:
            return 'critical'
    
    def _generate_summary(self, blacklist_results: List[Dict[str, Any]], blacklisted_count: int) -> str:
        """Generate human-readable summary of blacklist results."""
        if blacklisted_count == 0:
            return f"Domain is not listed on any of the {len(blacklist_results)} checked blacklists."
        
        listed_blacklists = [r for r in blacklist_results if r['listed']]
        high_severity = [r for r in listed_blacklists if r['severity'] == 'high']
        medium_severity = [r for r in listed_blacklists if r['severity'] == 'medium']
        
        if high_severity:
            bl_names = [r['name'] for r in high_severity]
            return f"Domain is listed on {len(high_severity)} high-severity blacklist(s): {', '.join(bl_names)}"
        elif medium_severity:
            bl_names = [r['name'] for r in medium_severity]
            return f"Domain is listed on {len(medium_severity)} medium-severity blacklist(s): {', '.join(bl_names)}"
        else:
            return f"Domain is listed on {blacklisted_count} blacklist(s) but none are high-severity."
    
    async def get_blacklist_info(self) -> Dict[str, Any]:
        """Get information about available blacklists."""
        return {
            'total_blacklists': len(self.blacklists),
            'blacklists': self.blacklists,
            'categories': {
                'spam': len([b for b in self.blacklists.values() if b['category'] == 'spam']),
                'exploits': len([b for b in self.blacklists.values() if b['category'] == 'exploits']),
                'policy': len([b for b in self.blacklists.values() if b['category'] == 'policy']),
                'reputation': len([b for b in self.blacklists.values() if b['category'] == 'reputation']),
                'abuse': len([b for b in self.blacklists.values() if b['category'] == 'abuse']),
                'malware': len([b for b in self.blacklists.values() if b['category'] == 'malware']),
                'proxy': len([b for b in self.blacklists.values() if b['category'] == 'proxy']),
                'relay': len([b for b in self.blacklists.values() if b['category'] == 'relay']),
                'bogon': len([b for b in self.blacklists.values() if b['category'] == 'bogon']),
                'backscatter': len([b for b in self.blacklists.values() if b['category'] == 'backscatter'])
            }
        }


# Global blacklist service instance
blacklist_service = BlacklistService() 