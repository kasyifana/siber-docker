# src/tools/header_analyzer.py

import aiohttp
from typing import Dict
from loguru import logger

class HeaderAnalyzer:
    def __init__(self):
        # EXPANDED security headers check - more comprehensive
        self.required_headers = {
            'Strict-Transport-Security': {
                'severity': 'high',
                'impact': 'Man-in-the-middle attacks, SSL stripping'
            },
            'Content-Security-Policy': {
                'severity': 'high',
                'impact': 'XSS attacks, data injection, code execution'
            },
            'X-Frame-Options': {
                'severity': 'medium',
                'impact': 'Clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'severity': 'medium',
                'impact': 'MIME sniffing attacks'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'impact': 'Information leakage'
            },
            'Permissions-Policy': {
                'severity': 'low',
                'impact': 'Unwanted feature access'
            },
            'X-XSS-Protection': {
                'severity': 'medium',
                'impact': 'XSS attacks (legacy browsers)'
            },
            'Cross-Origin-Opener-Policy': {
                'severity': 'medium',
                'impact': 'Cross-origin attacks'
            },
            'Cross-Origin-Resource-Policy': {
                'severity': 'medium',
                'impact': 'Resource theft attacks'
            },
            'Cross-Origin-Embedder-Policy': {
                'severity': 'low',
                'impact': 'Spectre attacks'
            },
            'Expect-CT': {
                'severity': 'low',
                'impact': 'Certificate transparency issues'
            },
            'Feature-Policy': {
                'severity': 'low',
                'impact': 'Browser feature abuse'
            }
        }
        logger.info("Header analyzer initialized")

    async def detect_technologies(self, url: str) -> Dict:
        """
        Detect web technologies via headers
        
        Args:
            url: Target URL
        
        Returns:
            Detected technologies
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, ssl=False) as response:
                    headers = response.headers
                    
                    technologies = {}
                    
                    if 'Server' in headers:
                        technologies['server'] = headers['Server']
                    
                    if 'X-Powered-By' in headers:
                        technologies['x-powered-by'] = headers['X-Powered-By']
                        
                    logger.info(f"Technologies found for {url}: {technologies}")
                    return {
                        'url': url,
                        'technologies': technologies
                    }
        except Exception as e:
            logger.error(f"Technology detection error for {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e)
            }
    
    async def analyze(self, url: str) -> Dict:
        """
        Analyze security headers
        
        Args:
            url: Target URL
        
        Returns:
            Analysis results
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, ssl=False) as response:
                    headers = response.headers
                    
                    results = {
                        'url': url,
                        'headers': {},
                        'score': 0,
                        'issues': []
                    }
                    
                    # Check each required header
                    for header, info in self.required_headers.items():
                        if header in headers:
                            results['headers'][header] = {
                                'present': True,
                                'value': headers[header],
                                'assessment': self._assess_header_value(header, headers[header])
                            }
                            results['score'] += 20
                        else:
                            results['headers'][header] = {
                                'present': False,
                                'impact': info['impact'],
                                'severity': info['severity']
                            }
                            results['issues'].append(f"Missing {header}")
                    
                    # Check for information disclosure - MORE AGGRESSIVE
                    if 'Server' in headers:
                        results['issues'].append(f"Server version exposed: {headers['Server']}")
                    
                    if 'X-Powered-By' in headers:
                        results['issues'].append(f"Technology exposed: {headers['X-Powered-By']}")
                    
                    if 'X-AspNet-Version' in headers:
                        results['issues'].append(f"ASP.NET version exposed: {headers['X-AspNet-Version']}")
                    
                    if 'X-AspNetMvc-Version' in headers:
                        results['issues'].append(f"ASP.NET MVC version exposed: {headers['X-AspNetMvc-Version']}")
                    
                    # Check for weak/deprecated headers
                    if 'X-XSS-Protection' in headers and '0' in headers['X-XSS-Protection']:
                        results['issues'].append("XSS Protection is DISABLED")
                    
                    # Check for permissive CORS
                    if 'Access-Control-Allow-Origin' in headers:
                        cors = headers['Access-Control-Allow-Origin']
                        if cors == '*':
                            results['issues'].append("CRITICAL: CORS allows ALL origins (*)")
                        results['issues'].append(f"CORS enabled for: {cors}")
                    
                    # Check for cache control issues
                    if 'Cache-Control' not in headers:
                        results['issues'].append("Missing Cache-Control header")
                    elif 'no-store' not in headers.get('Cache-Control', ''):
                        results['issues'].append("Sensitive data might be cached")
                    
                    # Check for cookie security
                    if 'Set-Cookie' in headers:
                        cookie = headers['Set-Cookie']
                        if 'Secure' not in cookie:
                            results['issues'].append("Cookie missing Secure flag")
                        if 'HttpOnly' not in cookie:
                            results['issues'].append("Cookie missing HttpOnly flag")
                        if 'SameSite' not in cookie:
                            results['issues'].append("Cookie missing SameSite flag")
                    
                    logger.info(f"Header analysis completed for {url}: Score {results['score']}/100")
                    return results
                    
        except Exception as e:
            logger.error(f"Header analysis error for {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'headers': {},
                'score': 0
            }
    
    def _assess_header_value(self, header: str, value: str) -> str:
        """Assess the quality of header value"""
        assessments = {
            'Strict-Transport-Security': self._assess_hsts(value),
            'Content-Security-Policy': self._assess_csp(value),
            'X-Frame-Options': self._assess_xfo(value),
            'X-Content-Type-Options': self._assess_xcto(value)
        }
        return assessments.get(header, 'Present')
    
    def _assess_hsts(self, value: str) -> str:
        if 'max-age=31536000' in value and 'includeSubDomains' in value:
            return 'Strong'
        elif 'max-age' in value:
            return 'Adequate'
        return 'Weak'
    
    def _assess_csp(self, value: str) -> str:
        if 'default-src' in value and 'unsafe-inline' not in value:
            return 'Strong'
        elif 'default-src' in value:
            return 'Adequate'
        return 'Weak'
    
    def _assess_xfo(self, value: str) -> str:
        if value.upper() in ['DENY', 'SAMEORIGIN']:
            return 'Strong'
        return 'Adequate'
    
    def _assess_xcto(self, value: str) -> str:
        return 'Strong' if value == 'nosniff' else 'Adequate'