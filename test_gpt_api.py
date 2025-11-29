#!/usr/bin/env python3
"""
Test script to verify OpenRouter API connection and functionality.

This script tests:
1. API key configuration
2. OpenRouter API connectivity
3. GPT summarizer functionality
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_api_key_configuration():
    """Test if OpenRouter API key is configured."""
    print("=" * 60)
    print("🔑 Testing API Key Configuration")
    print("=" * 60)
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    if not api_key:
        print("❌ OPENROUTER_API_KEY not found in environment variables")
        print("   Please add OPENROUTER_API_KEY to your .env file")
        return False
    
    if api_key == "your_openrouter_api_key" or api_key.startswith("your_"):
        print("❌ OPENROUTER_API_KEY appears to be a placeholder value")
        print("   Please set a valid OpenRouter API key in your .env file")
        return False
    
    # Mask the key for display (show first 7 and last 4 characters)
    masked_key = f"{api_key[:7]}...{api_key[-4:]}" if len(api_key) > 11 else "***"
    print(f"✅ API Key found: {masked_key}")
    return True

def test_openrouter_connection():
    """Test OpenRouter API connection with a simple request."""
    print("\n" + "=" * 60)
    print("🌐 Testing OpenRouter API Connection")
    print("=" * 60)
    
    try:
        import requests
        import json
        
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            print("❌ Cannot test: API key not configured")
            return False
        
        # Prepare headers
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        # Add optional headers if configured
        site_url = os.getenv("OPENROUTER_SITE_URL")
        site_name = os.getenv("OPENROUTER_SITE_NAME")
        if site_url:
            headers["HTTP-Referer"] = site_url
        if site_name:
            headers["X-Title"] = site_name
        
        # Prepare payload
        payload = {
            "model": "openai/gpt-4o-mini",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant."
                },
                {
                    "role": "user",
                    "content": "Say 'API connection successful' if you can read this."
                }
            ],
            "max_tokens": 20
        }
        
        # Make a simple test request
        print("📡 Sending test request to OpenRouter API...")
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            data=json.dumps(payload),
            timeout=30
        )
        
        response.raise_for_status()
        result_data = response.json()
        
        if "choices" in result_data and len(result_data["choices"]) > 0:
            result = result_data["choices"][0]["message"]["content"].strip()
            print(f"✅ API Connection Successful!")
            print(f"   Response: {result}")
            return True
        else:
            print(f"❌ Unexpected response format: {result_data}")
            return False
        
    except ImportError:
        print("❌ requests package not installed")
        print("   Run: pip install requests")
        return False
    except requests.exceptions.RequestException as e:
        error_msg = str(e)
        print(f"❌ API Connection Failed: {error_msg}")
        
        # Provide helpful error messages
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                error_message = error_detail.get('error', {}).get('message', 'Unknown error')
                print(f"   Error details: {error_message}")
                
                if "401" in str(e.response.status_code) or "Invalid" in error_message:
                    print("   → Your API key is invalid. Please check your OpenRouter API key.")
                elif "429" in str(e.response.status_code) or "quota" in error_message.lower():
                    print("   → ⚠️  QUOTA/RATE LIMIT: Your OpenRouter account has exceeded its quota or rate limit.")
                    print("   → Please check your OpenRouter account: https://openrouter.ai/keys")
                elif "insufficient" in error_message.lower():
                    print("   → ⚠️  INSUFFICIENT QUOTA: Please check your OpenRouter account billing.")
            except:
                print(f"   Response status: {e.response.status_code}")
                print(f"   Response text: {e.response.text[:200]}")
        else:
            if "Network" in error_msg or "Connection" in error_msg:
                print("   → Network connection issue. Please check your internet connection.")
            else:
                print("   → Please check your OpenRouter API key and account status.")
        
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False

def test_gpt_summarizer():
    """Test the GPT summarizer with sample scan data."""
    print("\n" + "=" * 60)
    print("🤖 Testing GPT Summarizer")
    print("=" * 60)
    
    try:
        # Import after checking API key
        from app.utils.gpt_summarizer import gpt_summarizer
        
        if not gpt_summarizer.is_available():
            print("❌ GPT Summarizer not available (API key not configured)")
            return False
        
        # Create sample scan data
        sample_scan_data = {
            "domain": "example.com",
            "score": 75,
            "overall_status": "medium_risk",
            "recommendations": [
                "Implement DMARC policy",
                "Configure SPF record properly",
                "Enable TLS-RPT reporting"
            ],
            "risk_assessment": {
                "level": "medium_risk",
                "severity": "Moderate",
                "description": "A domain with a medium security risk level shows partial implementation of email security protocols.",
                "action_required": "Action recommended",
                "score": 75,
                "critical_vulnerabilities": [
                    "DMARC record missing",
                    "SPF record incomplete"
                ]
            },
            "summary": [
                "SPF record found but incomplete",
                "DKIM records found",
                "DMARC record missing"
            ],
            "protocol_status": {
                "spf": {"exists": True, "status": "warning"},
                "dkim": {"exists": True, "status": "pass"},
                "dmarc": {"exists": False, "status": "not_found"}
            },
            "scoring_breakdown": {
                "core_authentication": {
                    "total_points": 70,
                    "earned_points": 50
                },
                "policy_enforcement": {
                    "total_points": 20,
                    "earned_points": 10
                }
            }
        }
        
        print("📝 Generating AI summary for sample scan data...")
        summary = gpt_summarizer.generate_summary(sample_scan_data)
        
        if summary:
            print("✅ GPT Summarizer Working!")
            print(f"\n📄 Generated Summary ({len(summary)} characters):")
            print("-" * 60)
            print(summary[:500] + "..." if len(summary) > 500 else summary)
            print("-" * 60)
            return True
        else:
            print("❌ GPT Summarizer returned None")
            print("   Check the error logs above for details")
            return False
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure you're running from the project root directory")
        return False
    except Exception as e:
        print(f"❌ GPT Summarizer test failed: {str(e)}")
        return False

def main():
    """Run all tests."""
    print("\n" + "🧪 OpenRouter API Test Suite".center(60))
    print("=" * 60)
    
    results = []
    
    # Test 1: API Key Configuration
    results.append(("API Key Configuration", test_api_key_configuration()))
    
    # Test 2: OpenRouter Connection (only if API key is configured)
    if results[0][1]:
        results.append(("OpenRouter API Connection", test_openrouter_connection()))
        
        # Test 3: GPT Summarizer (only if connection works)
        if results[1][1]:
            results.append(("GPT Summarizer", test_gpt_summarizer()))
    else:
        print("\n⚠️  Skipping API connection tests (API key not configured)")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print("=" * 60)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! OpenRouter API is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

