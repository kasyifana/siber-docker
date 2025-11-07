# src/tools/subdomain_enum.py

import asyncio
import aiohttp
import dns.resolver
from typing import Dict, List
from loguru import logger

class SubdomainEnumerator:
    def __init__(self):
        self.wordlist = self._load_wordlist()
        logger.info("Subdomain enumerator initialized")
    
    def _load_wordlist(self) -> List[str]:
        """Load subdomain wordlist"""
        # Common subdomains
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp',
            'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm',
            'autodiscover', 'autoconfig', 'mobile', 'api', 'dev',
            'test', 'staging', 'admin', 'portal', 'vpn', 'cdn',
            'blog', 'shop', 'store', 'app', 'static', 'media',
            'assets', 'images', 'downloads', 'docs', 'support'
        ]
    
    async def enumerate(
        self,
        domain: str,
        method: str = "all"
    ) -> Dict:
        """
        Enumerate subdomains
        
        Args:
            domain: Target domain
            method: Enumeration method (dns, certificate, brute, all)
        
        Returns:
            Enumeration results
        """
        subdomains = set()
        
        try:
            if method in ['dns', 'all']:
                dns_results = await self._enumerate_dns(domain)
                subdomains.update(dns_results)
            
            if method in ['certificate', 'all']:
                cert_results = await self._enumerate_certificate(domain)
                subdomains.update(cert_results)
            
            if method in ['brute', 'all']:
                brute_results = await self._enumerate_brute(domain)
                subdomains.update(brute_results)
            
            # Verify and get IPs
            verified = await self._verify_subdomains(list(subdomains))
            
            logger.info(f"Found {len(verified)} subdomains for {domain}")
            
            return {
                'domain': domain,
                'subdomains': verified,
                'count': len(verified),
                'method': method
            }
            
        except Exception as e:
            logger.error(f"Subdomain enumeration error for {domain}: {str(e)}")
            return {
                'domain': domain,
                'error': str(e),
                'subdomains': []
            }
    
    async def _enumerate_dns(self, domain: str) -> List[str]:
        """Enumerate via DNS records"""
        subdomains = []
        
        try:
            # Query different record types
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        if hasattr(rdata, 'target'):
                            subdomain = str(rdata.target).rstrip('.')
                            if domain in subdomain:
                                subdomains.append(subdomain)
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"DNS enumeration error: {str(e)}")
        
        return subdomains
    
    async def _enumerate_certificate(self, domain: str) -> List[str]:
        """Enumerate via SSL certificate (crt.sh)"""
        subdomains = []
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data:
                            name = entry.get('name_value', '')
                            for subdomain in name.split('\n'):
                                subdomain = subdomain.strip().replace('*.', '')
                                if subdomain.endswith(domain):
                                    subdomains.append(subdomain)
        
        except Exception as e:
            logger.debug(f"Certificate enumeration error: {str(e)}")
        
        return list(set(subdomains))
    
    async def _enumerate_brute(self, domain: str) -> List[str]:
        """Enumerate via brute force"""
        subdomains = []
        tasks = []
        
        async def check_subdomain(prefix: str):
            subdomain = f"{prefix}.{domain}"
            try:
                # Try DNS resolution
                answers = await asyncio.to_thread(
                    dns.resolver.resolve,
                    subdomain,
                    'A'
                )
                if answers:
                    return subdomain
            except:
                pass
            return None
        
        # Create tasks for all prefixes
        for prefix in self.wordlist:
            tasks.append(check_subdomain(prefix))
        
        # Execute with limited concurrency
        results = await asyncio.gather(*tasks)
        subdomains = [s for s in results if s is not None]
        
        return subdomains
    
    async def _verify_subdomains(self, subdomains: List[str]) -> List[Dict]:
        """Verify subdomains and get additional info"""
        verified = []
        
        async def verify(subdomain: str):
            try:
                # Resolve IP
                answers = await asyncio.to_thread(
                    dns.resolver.resolve,
                    subdomain,
                    'A'
                )
                ip = str(answers[0]) if answers else None
                
                # Check HTTP status
                status = await self._check_http_status(subdomain)
                
                return {
                    'name': subdomain,
                    'ip': ip,
                    'status': status
                }
            except:
                return None
        
        tasks = [verify(s) for s in subdomains]
        results = await asyncio.gather(*tasks)
        
        verified = [r for r in results if r is not None]
        return verified
    
    async def _check_http_status(self, subdomain: str) -> str:
        """Check HTTP status of subdomain"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{subdomain}",
                    timeout=5,
                    ssl=False
                ) as response:
                    return f"{response.status} {response.reason}"
        except:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"http://{subdomain}",
                        timeout=5
                    ) as response:
                        return f"{response.status} {response.reason}"
            except:
                return "unreachable"