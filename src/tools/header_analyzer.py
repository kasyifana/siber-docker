# src/tools/header_analyzer.py

import aiohttp
from typing import Dict
from loguru import logger

class HeaderAnalyzer:
    def __init__(self):
        self.required_headers = {
            'Strict-Transport-Security': {
                'severity': 'high',
                'impact': 'Man-in-the-middle attacks, SSL stripping'
            },
            'Content-Security-Policy': {
                'severity': 'high',
                'impact': 'XSS attacks, data injection'
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
            }
        }
        logger.info("Header analyzer initialized")
    
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
                async with session.get(url, timeout=10) as response:
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
                    
                    # Check for information disclosure
                    if 'Server' in headers:
                        results['issues'].append(f"Server version exposed: {headers['Server']}")
                    
                    if 'X-Powered-By' in headers:
                        results['issues'].append(f"Technology exposed: {headers['X-Powered-By']}")
                    
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