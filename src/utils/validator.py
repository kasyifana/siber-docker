# src/utils/validator.py

import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional
from loguru import logger

class TargetValidator:
    """Validate and sanitize security audit targets"""
    
    def __init__(self):
        # Blocked networks (private IPs, localhost, etc.)
        self.blocked_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
        ]
        
        # Regex patterns
        self.domain_pattern = re.compile(
            r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$',
            re.IGNORECASE
        )
        
        self.ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$'
        )
        
        logger.info("Target validator initialized")
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL
        
        Args:
            url: URL to validate
        
        Returns:
            True if valid and safe, False otherwise
        """
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                logger.warning(f"Invalid URL scheme: {parsed.scheme}")
                return False
            
            # Check hostname
            if not parsed.hostname:
                logger.warning("URL missing hostname")
                return False
            
            # Validate hostname
            if not self.validate_hostname(parsed.hostname):
                return False
            
            # Check for dangerous ports
            if parsed.port and parsed.port in [22, 23, 3389]:
                logger.warning(f"Blocked port {parsed.port} in URL")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"URL validation error: {str(e)}")
            return False
    
    def validate_hostname(self, hostname: str) -> bool:
        """
        Validate hostname
        
        Args:
            hostname: Hostname to validate
        
        Returns:
            True if valid and safe, False otherwise
        """
        try:
            # Check if it's an IP address
            if self.ip_pattern.match(hostname):
                return self.validate_ip(hostname)
            
            # Check if it's a valid domain
            if not self.domain_pattern.match(hostname):
                logger.warning(f"Invalid hostname format: {hostname}")
                return False
            
            # Check for localhost
            if hostname.lower() in ['localhost', 'localhost.localdomain']:
                logger.warning("Localhost is blocked")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Hostname validation error: {str(e)}")
            return False
    
    def validate_ip(self, ip: str) -> bool:
        """
        Validate IP address
        
        Args:
            ip: IP address to validate
        
        Returns:
            True if valid and safe, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is in blocked networks
            for network in self.blocked_networks:
                if ip_obj in network:
                    logger.warning(f"IP {ip} is in blocked network {network}")
                    return False
            
            # Check if it's a private IP
            if ip_obj.is_private:
                logger.warning(f"Private IP blocked: {ip}")
                return False
            
            # Check if it's a loopback
            if ip_obj.is_loopback:
                logger.warning(f"Loopback IP blocked: {ip}")
                return False
            
            # Check if it's multicast
            if ip_obj.is_multicast:
                logger.warning(f"Multicast IP blocked: {ip}")
                return False
            
            return True
            
        except ValueError as e:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def validate_domain(self, domain: str) -> bool:
        """
        Validate domain name
        
        Args:
            domain: Domain to validate
        
        Returns:
            True if valid, False otherwise
        """
        try:
            # Remove protocol if present
            domain = domain.replace('http://', '').replace('https://', '')
            
            # Remove path if present
            domain = domain.split('/')[0]
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            # Check format
            if not self.domain_pattern.match(domain):
                logger.warning(f"Invalid domain format: {domain}")
                return False
            
            # Check length
            if len(domain) > 253:
                logger.warning(f"Domain too long: {domain}")
                return False
            
            # Check each label
            labels = domain.split('.')
            for label in labels:
                if len(label) > 63:
                    logger.warning(f"Domain label too long: {label}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Domain validation error: {str(e)}")
            return False
    
    def validate_target(self, target: str) -> bool:
        """
        Validate any target (URL, IP, hostname, domain)
        
        Args:
            target: Target to validate
        
        Returns:
            True if valid, False otherwise
        """
        # Try as URL
        if target.startswith('http://') or target.startswith('https://'):
            return self.validate_url(target)
        
        # Try as IP
        if self.ip_pattern.match(target):
            return self.validate_ip(target)
        
        # Try as hostname/domain
        return self.validate_hostname(target)
    
    def sanitize_input(self, input_str: str) -> str:
        """
        Sanitize user input to prevent injection
        
        Args:
            input_str: Input string
        
        Returns:
            Sanitized string
        """
        # Remove dangerous characters
        dangerous_chars = ['|', ';', '&', '$', '`', '\n', '\r']
        sanitized = input_str
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()
