# src/tools/ssl_checker.py

import ssl
import socket
import asyncio
from datetime import datetime
from typing import Dict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from loguru import logger

class SSLChecker:
    def __init__(self):
        self.timeout = 10
        logger.info("SSL checker initialized")
    
    async def analyze(
        self,
        hostname: str,
        port: int = 443
    ) -> Dict:
        """
        Analyze SSL/TLS configuration
        
        Args:
            hostname: Target hostname
            port: SSL port (default 443)
        
        Returns:
            SSL analysis results
        """
        try:
            # Remove protocol if present
            hostname = hostname.replace('https://', '').replace('http://', '')
            hostname = hostname.split('/')[0]
            hostname = hostname.split(':')[0]
            
            logger.info(f"Analyzing SSL/TLS for {hostname}:{port}")
            
            # Get certificate
            cert_info = await self._get_certificate(hostname, port)
            
            # Check supported protocols
            protocols = await self._check_protocols(hostname, port)
            
            # Check cipher suites
            ciphers = await self._check_ciphers(hostname, port)
            
            # Analyze vulnerabilities
            issues = self._analyze_vulnerabilities(cert_info, protocols, ciphers)
            
            # Calculate grade
            grade = self._calculate_grade(cert_info, protocols, issues)
            
            results = {
                'hostname': hostname,
                'port': port,
                'certificate': cert_info,
                'protocols': protocols,
                'ciphers': ciphers,
                'issues': issues,
                'grade': grade
            }
            
            logger.info(f"SSL analysis completed for {hostname}: Grade {grade}")
            
            return results
            
        except Exception as e:
            logger.error(f"SSL analysis error for {hostname}: {str(e)}")
            return {
                'hostname': hostname,
                'port': port,
                'error': str(e),
                'grade': 'F'
            }
    
    async def _get_certificate(self, hostname: str, port: int) -> Dict:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    # Parse certificate
                    cert = x509.load_pem_x509_certificate(
                        cert_pem.encode(),
                        default_backend()
                    )
                    
                    # Extract information
                    return {
                        'subject': cert.subject.rfc4514_string(),
                        'issuer': cert.issuer.rfc4514_string(),
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'not_before': cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S'),
                        'not_after': cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S'),
                        'valid_until': cert.not_valid_after_utc.strftime('%Y-%m-%d'),
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 'N/A',
                        'san': self._get_san(cert),
                        'expired': datetime.now() > cert.not_valid_after_utc.replace(tzinfo=None)
                    }
                    
        except Exception as e:
            logger.error(f"Certificate retrieval error: {str(e)}")
            return {'error': str(e)}
    
    def _get_san(self, cert) -> list:
        """Get Subject Alternative Names"""
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return [name.value for name in san_ext.value]
        except:
            return []
    
    async def _check_protocols(self, hostname: str, port: int) -> list:
        """Check supported SSL/TLS protocols"""
        protocols = []
        
        protocol_versions = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Old
            'SSLv3': ssl.PROTOCOL_SSLv23,  # Old
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }
        
        # Add TLS 1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocol_versions['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
        
        for name, protocol in protocol_versions.items():
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        protocols.append({
                            'name': name,
                            'status': 'supported',
                            'secure': name not in ['SSLv2', 'SSLv3', 'TLSv1.0']
                        })
            except:
                protocols.append({
                    'name': name,
                    'status': 'not supported',
                    'secure': True
                })
        
        return protocols
    
    async def _check_ciphers(self, hostname: str, port: int) -> list:
        """Check supported cipher suites"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    return [{
                        'name': cipher[0],
                        'protocol': cipher[1],
                        'bits': cipher[2]
                    }]
        except:
            return []
    
    def _analyze_vulnerabilities(
        self,
        cert_info: Dict,
        protocols: list,
        ciphers: list
    ) -> list:
        """Analyze SSL/TLS vulnerabilities"""
        issues = []
        
        # Check certificate issues
        if cert_info.get('expired'):
            issues.append("Certificate has expired")
        
        if cert_info.get('key_size') and cert_info['key_size'] < 2048:
            issues.append(f"Weak key size: {cert_info['key_size']} bits (should be at least 2048)")
        
        if 'sha1' in cert_info.get('signature_algorithm', '').lower():
            issues.append("Certificate uses weak SHA-1 signature algorithm")
        
        # Check protocol issues
        for protocol in protocols:
            if protocol['status'] == 'supported' and not protocol['secure']:
                issues.append(f"Insecure protocol {protocol['name']} is enabled")
        
        # Check if modern TLS is supported
        modern_tls = any(p['name'] in ['TLSv1.2', 'TLSv1.3'] and p['status'] == 'supported' for p in protocols)
        if not modern_tls:
            issues.append("Modern TLS protocols (1.2+) not supported")
        
        return issues
    
    def _calculate_grade(
        self,
        cert_info: Dict,
        protocols: list,
        issues: list
    ) -> str:
        """Calculate SSL grade"""
        score = 100
        
        # Deduct points for issues
        for issue in issues:
            if 'expired' in issue.lower():
                score -= 50
            elif 'weak' in issue.lower():
                score -= 20
            elif 'insecure protocol' in issue.lower():
                score -= 15
            elif 'sha-1' in issue.lower():
                score -= 10
            else:
                score -= 5
        
        # Grade based on score
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
