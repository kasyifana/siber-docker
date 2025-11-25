
import asyncio
import sys
import os
from loguru import logger

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

from tools.subdomain_enum import SubdomainEnumerator

async def verify():
    print("Initializing SubdomainEnumerator...")
    scanner = SubdomainEnumerator()
    
    # Check wordlist size
    print(f"Wordlist size: {len(scanner.wordlist)}")
    if len(scanner.wordlist) > 50:
        print("PASS: Wordlist expanded")
    else:
        print("FAIL: Wordlist not expanded")

    # Test DNS enumeration with a domain known to have MX records (google.com)
    domain = "google.com"
    print(f"\nScanning {domain} (DNS method only)...")
    
    results = await scanner.enumerate(domain, method="dns")
    
    subdomains = results.get('subdomains', [])
    print(f"Found {len(subdomains)} subdomains")
    
    # Check for MX records (smtp.google.com)
    mx_found = False
    for s in subdomains:
        name = s.get('name', '')
        print(f" - {name}")
        if 'smtp' in name:
            mx_found = True
            
    if mx_found:
        print("PASS: MX records detected")
    else:
        print("FAIL: MX records NOT detected")

if __name__ == "__main__":
    asyncio.run(verify())
