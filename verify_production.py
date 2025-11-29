#!/usr/bin/env python3
"""
Production readiness verification script.
Tests all critical endpoints and features.
"""

import requests
import sys
import time

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint."""
    print("✓ Testing health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        assert response.status_code == 200
        print("  ✅ Health check passed")
        return True
    except Exception as e:
        print(f"  ❌ Health check failed: {e}")
        return False

def test_reverse_dns():
    """Test reverse DNS endpoint."""
    print("✓ Testing reverse DNS endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/security/reverse-dns/8.8.8.8", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['data']['hostname'] == 'dns.google'
        print("  ✅ Reverse DNS check passed")
        return True
    except Exception as e:
        print(f"  ❌ Reverse DNS check failed: {e}")
        return False

def test_port_scan():
    """Test port scanner endpoint."""
    print("✓ Testing port scanner endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/security/port-scan/smtp.gmail.com?timeout=2", timeout=15)
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert 'open_ports' in data['data']
        print(f"  ✅ Port scan passed (found {len(data['data']['open_ports'])} open ports)")
        return True
    except Exception as e:
        print(f"  ❌ Port scan failed: {e}")
        return False

def test_blacklist_check():
    """Test blacklist checking endpoint."""
    print("✓ Testing blacklist check endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/security/blacklist-check/8.8.8.8?timeout=2", timeout=20)
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert 'is_blacklisted' in data['data']
        assert data['data']['total_checked'] >= 8
        print(f"  ✅ Blacklist check passed (checked {data['data']['total_checked']} RBLs)")
        return True
    except Exception as e:
        print(f"  ❌ Blacklist check failed: {e}")
        return False

def test_enhanced_spf():
    """Test enhanced SPF analysis."""
    print("✓ Testing enhanced SPF analysis...")
    try:
        # Using a test domain - adjust as needed
        response = requests.get(f"{BASE_URL}/api/v1/security/spf/example.com", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        # Check for new fields
        spf_data = data['data']
        assert 'strength' in spf_data
        assert 'lookup_count' in spf_data
        assert 'mechanism_details' in spf_data
        print("  ✅ Enhanced SPF analysis passed")
        return True
    except Exception as e:
        print(f"  ❌ Enhanced SPF analysis failed: {e}")
        return False

def test_api_docs():
    """Test API documentation availability."""
    print("✓ Testing API documentation...")
    try:
        response = requests.get(f"{BASE_URL}/docs", timeout=5)
        assert response.status_code == 200
        print("  ✅ Swagger UI available")
        
        response = requests.get(f"{BASE_URL}/redoc", timeout=5)
        assert response.status_code == 200
        print("  ✅ ReDoc available")
        return True
    except Exception as e:
        print(f"  ❌ API documentation check failed: {e}")
        return False

def main():
    """Run all production checks."""
    print("=" * 60)
    print("PRODUCTION READINESS VERIFICATION")
    print("=" * 60)
    print()
    
    # Check if server is running
    print("Checking if server is running...")
    try:
        requests.get(BASE_URL, timeout=2)
        print("✅ Server is running\n")
    except:
        print("❌ Server is not running. Please start the server first.")
        print("   Run: ./venv/bin/python run.py")
        sys.exit(1)
    
    # Run all tests
    tests = [
        test_health,
        test_api_docs,
        test_reverse_dns,
        test_port_scan,
        test_blacklist_check,
        test_enhanced_spf,
    ]
    
    results = []
    for test in tests:
        result = test()
        results.append(result)
        time.sleep(0.5)  # Small delay between tests
        print()
    
    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ ALL CHECKS PASSED - READY FOR PRODUCTION")
        sys.exit(0)
    else:
        print(f"\n❌ {total - passed} CHECK(S) FAILED - NOT READY FOR PRODUCTION")
        sys.exit(1)

if __name__ == "__main__":
    main()
