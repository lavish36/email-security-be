#!/usr/bin/env python3
"""Test script to verify enhanced SPF, DKIM, and DMARC analysis."""

import sys
import os
sys.path.append(os.getcwd())

from app.services.dns_service import DNSService
from app.utils.dns_utils import SPFParser, DKIMParser, DMARCParser

def test_enhanced_spf():
    print("=" * 80)
    print("Testing Enhanced SPF Analysis")
    print("=" * 80)
    
    # Test SPF with multiple includes
    spf_record = "v=spf1 include:_spf.google.com include:sendgrid.net ip4:192.0.2.0/24 ip6:2001:db8::/32 mx a -all"
    parsed = SPFParser.parse_spf_record(spf_record)
    
    print(f"\nSPF Record: {spf_record}")
    print(f"\nStrength: {parsed['strength']}")
    print(f"Lookup Count: {parsed['lookup_count']}")
    print(f"All Mechanism: {parsed['all_mechanism']}")
    print(f"\nMechanism Details:")
    for detail in parsed['mechanism_details']:
        print(f"  - {detail['type']}: {detail['value']}")
        print(f"    Description: {detail['description']}")
    print(f"\nWarnings: {parsed['warnings']}")
    
    # Test weak SPF
    print("\n" + "-" * 80)
    weak_spf = "v=spf1 +all"
    parsed_weak = SPFParser.parse_spf_record(weak_spf)
    print(f"\nWeak SPF Record: {weak_spf}")
    print(f"Strength: {parsed_weak['strength']}")
    print(f"Warnings: {parsed_weak['warnings']}")
    
    # Test SPF with too many lookups
    print("\n" + "-" * 80)
    many_lookups = "v=spf1 " + " ".join([f"include:spf{i}.example.com" for i in range(12)]) + " -all"
    parsed_many = SPFParser.parse_spf_record(many_lookups)
    print(f"\nSPF with many lookups")
    print(f"Lookup Count: {parsed_many['lookup_count']}")
    print(f"Warnings: {parsed_many['warnings']}")

def test_enhanced_dkim():
    print("\n" + "=" * 80)
    print("Testing Enhanced DKIM Analysis")
    print("=" * 80)
    
    # Test strong DKIM (2048-bit key simulation)
    strong_key = "v=DKIM1; k=rsa; p=" + "A" * 400  # Simulates 2048-bit key
    parsed_strong = DKIMParser.parse_dkim_record(strong_key)
    
    print(f"\nStrong DKIM Key (simulated 2048-bit)")
    print(f"Key Size: {parsed_strong['key_size']} bits")
    print(f"Security Profile: {parsed_strong['security_profile']}")
    print(f"Algorithm: {parsed_strong['algorithm']}")
    print(f"Warnings: {parsed_strong['warnings']}")
    
    # Test weak DKIM
    print("\n" + "-" * 80)
    weak_key = "v=DKIM1; k=rsa; p=" + "A" * 100  # Simulates 512-bit key
    parsed_weak = DKIMParser.parse_dkim_record(weak_key)
    
    print(f"\nWeak DKIM Key (simulated 512-bit)")
    print(f"Key Size: {parsed_weak['key_size']} bits")
    print(f"Security Profile: {parsed_weak['security_profile']}")
    print(f"Warnings: {parsed_weak['warnings']}")

def test_enhanced_dmarc():
    print("\n" + "=" * 80)
    print("Testing Enhanced DMARC Analysis")
    print("=" * 80)
    
    # Test strict DMARC
    strict_dmarc = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; adkim=s; aspf=s"
    parsed_strict = DMARCParser.parse_dmarc_record(strict_dmarc)
    
    print(f"\nStrict DMARC Record: {strict_dmarc}")
    print(f"Policy: {parsed_strict['policy']}")
    print(f"Policy Description: {parsed_strict['policy_description']}")
    print(f"Alignment Mode (DKIM): {parsed_strict['adkim']}")
    print(f"  Description: {parsed_strict['alignment_description']['dkim']}")
    print(f"Alignment Mode (SPF): {parsed_strict['aspf']}")
    print(f"  Description: {parsed_strict['alignment_description']['spf']}")
    
    # Test relaxed DMARC
    print("\n" + "-" * 80)
    relaxed_dmarc = "v=DMARC1; p=quarantine; rua=mailto:reports@example.com"
    parsed_relaxed = DMARCParser.parse_dmarc_record(relaxed_dmarc)
    
    print(f"\nRelaxed DMARC Record: {relaxed_dmarc}")
    print(f"Policy: {parsed_relaxed['policy']}")
    print(f"Policy Description: {parsed_relaxed['policy_description']}")
    print(f"Alignment Description (DKIM): {parsed_relaxed['alignment_description']['dkim']}")
    print(f"Alignment Description (SPF): {parsed_relaxed['alignment_description']['spf']}")
    
    # Test monitoring-only DMARC
    print("\n" + "-" * 80)
    monitor_dmarc = "v=DMARC1; p=none; rua=mailto:monitor@example.com"
    parsed_monitor = DMARCParser.parse_dmarc_record(monitor_dmarc)
    
    print(f"\nMonitoring DMARC Record: {monitor_dmarc}")
    print(f"Policy: {parsed_monitor['policy']}")
    print(f"Policy Description: {parsed_monitor['policy_description']}")

if __name__ == "__main__":
    test_enhanced_spf()
    test_enhanced_dkim()
    test_enhanced_dmarc()
    
    print("\n" + "=" * 80)
    print("All tests completed successfully!")
    print("=" * 80)
