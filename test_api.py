#!/usr/bin/env python3
"""
Domain Security API - Test Script

This script tests the main API endpoints to ensure they work correctly.
"""

import requests
import json
import time

# API base URL
BASE_URL = "http://localhost:8000"

def test_health_check():
    """Test the health check endpoint."""
    print("🔍 Testing health check...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed: {data['status']}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_root_endpoint():
    """Test the root endpoint."""
    print("🏠 Testing root endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Root endpoint: {data['message']}")
            return True
        else:
            print(f"❌ Root endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Root endpoint error: {e}")
        return False

def test_spf_check():
    """Test SPF check endpoint."""
    print("📧 Testing SPF check...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/security/spf/google.com")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ SPF check passed: {data['message']}")
            return True
        else:
            print(f"❌ SPF check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ SPF check error: {e}")
        return False

def test_dmarc_check():
    """Test DMARC check endpoint."""
    print("🛡️ Testing DMARC check...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/security/dmarc/google.com")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ DMARC check passed: {data['message']}")
            return True
        else:
            print(f"❌ DMARC check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ DMARC check error: {e}")
        return False

def test_mx_check():
    """Test MX check endpoint."""
    print("📮 Testing MX check...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/security/mx/google.com")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ MX check passed: {data['message']}")
            return True
        else:
            print(f"❌ MX check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ MX check error: {e}")
        return False

def test_whois_lookup():
    """Test WHOIS lookup endpoint."""
    print("🔍 Testing WHOIS lookup...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/intelligence/whois/google.com")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ WHOIS lookup passed: {data['message']}")
            return True
        else:
            print(f"❌ WHOIS lookup failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ WHOIS lookup error: {e}")
        return False

def test_spf_generator():
    """Test SPF generator endpoint."""
    print("🛠️ Testing SPF generator...")
    try:
        payload = {
            "domain": "example.com",
            "email_providers": ["google", "outlook"],
            "include_all": False,
            "custom_mechanisms": []
        }
        response = requests.post(f"{BASE_URL}/api/v1/generate/spf", json=payload)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ SPF generator passed: {data['message']}")
            return True
        else:
            print(f"❌ SPF generator failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ SPF generator error: {e}")
        return False

def test_dns_providers():
    """Test DNS providers endpoint."""
    print("🌐 Testing DNS providers...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/guides/providers")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ DNS providers passed: {data['message']}")
            return True
        else:
            print(f"❌ DNS providers failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ DNS providers error: {e}")
        return False

def test_comprehensive_scan():
    """Test comprehensive security scan endpoint."""
    print("🔍 Testing comprehensive security scan...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/security/scan/google.com")
        if response.status_code == 200:
            data = response.json()
            scan_data = data.get('data', {})
            
            # Check if overall_score is present
            if 'overall_score' in scan_data:
                overall_score = scan_data['overall_score']
                print(f"✅ Comprehensive scan passed: {data['message']}")
                print(f"   Overall Score: {overall_score}/100")
                return True
            else:
                print(f"❌ Comprehensive scan failed: overall_score field missing")
                return False
        else:
            print(f"❌ Comprehensive scan failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Comprehensive scan error: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Starting API Tests...")
    print("=" * 50)
    
    tests = [
        test_health_check,
        test_root_endpoint,
        test_spf_check,
        test_dmarc_check,
        test_mx_check,
        test_whois_lookup,
        test_spf_generator,
        test_dns_providers,
        test_comprehensive_scan
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
        time.sleep(0.5)  # Small delay between tests
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! API is working correctly.")
    else:
        print("⚠️ Some tests failed. Check the API logs for details.")
    
    print(f"📖 View API documentation at: {BASE_URL}/docs")

if __name__ == "__main__":
    main() 