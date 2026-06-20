#!/usr/bin/env python3
"""
Quick test script for WHOIS scanner
"""
from scanners.whois_scanner import scan_whois
import json
import sys

# Check whois package
print("=" * 60)
print("WHOIS Package Check")
print("=" * 60)

try:
    import whois
    print(f"✅ whois module found: {whois}")
    print(f"   Module file: {whois.__file__}")
except ImportError:
    print("❌ whois module not found")
    print("   Fix: pip install python-whois")
    sys.exit(1)

print("\n" + "=" * 60)
print("WHOIS Scanner Test")
print("=" * 60)

# Test domains
test_urls = [
    "google.com",
    "github.com",
    "example.com"
]

for url in test_urls:
    print(f"\nTesting: {url}")
    print("-" * 60)
    
    result = scan_whois(url)
    
    if result.get('success'):
        print(f"✅ Status: Success")
        print(f"   Domain: {result.get('domain', 'N/A')}")
        print(f"   Registrar: {result.get('registrar', 'N/A')}")
        print(f"   Created: {result.get('creation_date', 'N/A')}")
        print(f"   Expires: {result.get('expiration_date', 'N/A')}")
        age = result.get('domain_age_days', 'N/A')
        print(f"   Age: {age} days" if age != 'N/A' else f"   Age: {age}")
        ns = result.get('name_servers', [])
        print(f"   Name Servers: {', '.join(ns) if ns else 'N/A'}")
        status = result.get('status', [])
        print(f"   Status: {', '.join(status) if status else 'N/A'}")
    else:
        print(f"❌ Status: Failed")
        print(f"   Error: {result.get('error', 'Unknown error')}")

print("\n" + "=" * 60)
print("Test Complete")
print("=" * 60)
