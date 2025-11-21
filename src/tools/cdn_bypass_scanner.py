# src/tools/cdn_bypass_scanner.py

import aiohttp
import socket
from typing import Dict, List
from loguru import logger
from urllib.parse import urlparse

class CDNBypassScanner:
    def __init__(self):
        self.cdn_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare', 'cf-cache-status'],
            'vercel': ['x-vercel-id', 'vercel', 'x-vercel-cache'],
            'aws': ['x-amz-cf-id', 'cloudfront', 'x-amz-cf-pop'],
            'fastly': ['fastly', 'x-served-by', 'x-cache'],
            'akamai': ['akamai', 'x-akamai'],
            'netlify': ['x-nf-request-id', 'netlify'],
        }
        logger.info("CDN Bypass Scanner initialized")
    
    async def scan(self, url: str) -> Dict:
        """
        Comprehensive CDN detection and bypass scan
        
        Args:
            url: Target URL
        
        Returns:
            Detailed scan results with CDN vs Origin comparison
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            # Step 1: Detect CDN
            cdn_info = await self._detect_cdn(url)
            
            # Step 2: Get CDN-protected headers
            cdn_headers = await self._get_headers(url)
            
            # Step 3: Try to find origin IP
            origin_ips = await self._find_origin_ip(hostname)
            
            # Step 4: Scan origin directly (if found)
            origin_headers = {}
            if origin_ips:
                origin_headers = await self._scan_origin_directly(origin_ips[0], parsed.path or '/', parsed.scheme == 'https')
            
            # Step 5: Analyze differences
            analysis = self._analyze_protection(cdn_headers, origin_headers, cdn_info)
            
            return {
                'url': url,
                'cdn_detected': cdn_info['detected'],
                'cdn_provider': cdn_info['provider'],
                'cdn_headers': cdn_headers,
                'origin_ips': origin_ips,
                'origin_headers': origin_headers,
                'security_analysis': analysis,
                'bypass_possible': len(origin_ips) > 0,
                'real_vulnerabilities': analysis['real_vulnerabilities']
            }
            
        except Exception as e:
            logger.error(f"CDN bypass scan error: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'cdn_detected': False,
                'bypass_possible': False
            }
    
    async def _detect_cdn(self, url: str) -> Dict:
        """Detect if site is behind CDN"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, ssl=False) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    for provider, indicators in self.cdn_indicators.items():
                        for indicator in indicators:
                            if any(indicator.lower() in h for h in headers.keys()):
                                return {
                                    'detected': True,
                                    'provider': provider.upper(),
                                    'indicators': [h for h in headers.keys() if indicator.lower() in h]
                                }
                            if any(indicator.lower() in str(v).lower() for v in headers.values()):
                                return {
                                    'detected': True,
                                    'provider': provider.upper(),
                                    'indicators': ['header_value_match']
                                }
                    
                    # Check for generic CDN indicators
                    if 'server' in headers:
                        server = headers['server'].lower()
                        if any(cdn in server for cdn in ['cloudflare', 'cloudfront', 'vercel', 'netlify']):
                            return {
                                'detected': True,
                                'provider': server.split()[0].upper(),
                                'indicators': ['server_header']
                            }
                    
                    return {
                        'detected': False,
                        'provider': 'None',
                        'indicators': []
                    }
        except Exception as e:
            logger.error(f"CDN detection error: {str(e)}")
            return {'detected': False, 'provider': 'Unknown', 'error': str(e)}
    
    async def _get_headers(self, url: str) -> Dict:
        """Get all headers from URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, ssl=False) as response:
                    return dict(response.headers)
        except Exception as e:
            logger.error(f"Header retrieval error: {str(e)}")
            return {}
    
    async def _find_origin_ip(self, hostname: str) -> List[str]:
        """Try to find origin server IP addresses"""
        ips = []
        
        try:
            # DNS lookup
            addr_info = socket.getaddrinfo(hostname, None)
            for info in addr_info:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            
            logger.info(f"Found {len(ips)} IP(s) for {hostname}: {ips}")
            return ips
            
        except Exception as e:
            logger.error(f"Origin IP discovery error: {str(e)}")
            return []
    
    async def _scan_origin_directly(self, origin_ip: str, path: str, use_https: bool) -> Dict:
        """
        Scan origin server directly by IP (bypass CDN)
        WARNING: This might not work if origin requires SNI or blocks direct access
        """
        try:
            scheme = 'https' if use_https else 'http'
            url = f"{scheme}://{origin_ip}{path}"
            
            # Use connector to bypass SSL verification
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=10, allow_redirects=False) as response:
                    return dict(response.headers)
                    
        except Exception as e:
            logger.warning(f"Direct origin scan failed: {str(e)}")
            return {}
    
    def _analyze_protection(self, cdn_headers: Dict, origin_headers: Dict, cdn_info: Dict) -> Dict:
        """Analyze security differences between CDN and origin"""
        
        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy'
        ]
        
        cdn_security = {h: cdn_headers.get(h) for h in security_headers}
        origin_security = {h: origin_headers.get(h) for h in security_headers}
        
        # Find what CDN adds that origin lacks
        cdn_added_protection = []
        real_vulnerabilities = []
        
        for header in security_headers:
            cdn_has = cdn_security.get(header) is not None
            origin_has = origin_security.get(header) is not None
            
            if cdn_has and not origin_has:
                cdn_added_protection.append({
                    'header': header,
                    'added_by_cdn': True,
                    'cdn_value': cdn_security[header]
                })
                real_vulnerabilities.append({
                    'type': 'missing_security_header',
                    'header': header,
                    'severity': 'HIGH' if header in ['strict-transport-security', 'content-security-policy'] else 'MEDIUM',
                    'description': f"Origin server missing {header} - only protected by CDN",
                    'impact': "If CDN is bypassed, this vulnerability is exploitable"
                })
            elif not cdn_has and not origin_has:
                real_vulnerabilities.append({
                    'type': 'missing_security_header',
                    'header': header,
                    'severity': 'HIGH' if header in ['strict-transport-security', 'content-security-policy'] else 'MEDIUM',
                    'description': f"Missing {header} on both CDN and origin",
                    'impact': "Vulnerability exists even with CDN protection"
                })
        
        # Check for information disclosure in origin
        info_disclosure = []
        for header in ['server', 'x-powered-by', 'x-aspnet-version']:
            if origin_headers.get(header):
                info_disclosure.append({
                    'header': header,
                    'value': origin_headers[header],
                    'hidden_by_cdn': header not in cdn_headers or cdn_headers[header] != origin_headers[header]
                })
                real_vulnerabilities.append({
                    'type': 'information_disclosure',
                    'header': header,
                    'severity': 'LOW',
                    'description': f"Origin exposes {header}: {origin_headers[header]}",
                    'impact': "Attackers can fingerprint technology stack if CDN bypassed"
                })
        
        return {
            'cdn_protection_active': cdn_info['detected'],
            'cdn_provider': cdn_info['provider'],
            'cdn_added_headers': cdn_added_protection,
            'information_disclosure': info_disclosure,
            'real_vulnerabilities': real_vulnerabilities,
            'vulnerability_count': len(real_vulnerabilities),
            'security_score': max(0, 100 - (len(real_vulnerabilities) * 10)),
            'recommendation': self._generate_recommendations(real_vulnerabilities, cdn_info['detected'])
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict], has_cdn: bool) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if has_cdn and vulnerabilities:
            recommendations.append("⚠️ You are relying on CDN for security - this is DANGEROUS!")
            recommendations.append("🔧 Add security headers to your ORIGIN server (Next.js/Vercel config)")
            recommendations.append("🔒 Configure security headers in vercel.json or next.config.js")
        
        if any(v['type'] == 'missing_security_header' for v in vulnerabilities):
            recommendations.append("📝 Implement missing security headers in your application code")
        
        if any(v['type'] == 'information_disclosure' for v in vulnerabilities):
            recommendations.append("🚫 Hide server version and technology headers")
        
        if not has_cdn and vulnerabilities:
            recommendations.append("⚡ Consider using a CDN for DDoS protection")
        
        return recommendations
