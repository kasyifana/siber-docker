# src/config/settings.py

from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Server Configuration
    MCP_SERVER_HOST: str = "0.0.0.0"
    MCP_SERVER_PORT: int = 8080
    
    # Security Settings
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 300  # seconds
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 60  # seconds
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_FILE: str = "/app/logs/security-audit.log"
    
    # Database
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "mcp_security"
    POSTGRES_USER: str = "mcpuser"
    POSTGRES_PASSWORD: str = "changeme"
    
    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    
    # Tool Paths
    NMAP_PATH: str = "/usr/bin/nmap"
    NIKTO_PATH: str = "/usr/local/bin/nikto"
    SQLMAP_PATH: str = "/usr/bin/sqlmap"
    ZAP_PATH: str = "/opt/ZAP_2.14.0/zap.sh"
    
    # Wordlists
    SUBDOMAIN_WORDLIST: str = "/app/data/wordlists/subdomains.txt"
    XSS_PAYLOAD_LIST: str = "/app/data/payloads/xss.txt"
    SQLI_PAYLOAD_LIST: str = "/app/data/payloads/sqli.txt"
    
    # Output
    REPORT_DIR: str = "/app/reports"
    DATA_DIR: str = "/app/data"
    
    # Scan Configuration
    DEFAULT_NMAP_PORTS: str = "1-1000"
    DEFAULT_NMAP_ARGS: str = "-T4 -F"
    DEFAULT_NIKTO_TUNING: str = "1,2,3,4,5,6,7,8,9"
    
    # Timeouts
    HTTP_TIMEOUT: int = 10
    DNS_TIMEOUT: int = 5
    SSL_TIMEOUT: int = 10
    
    # Allowed Targets (for safety)
    BLOCKED_NETWORKS: list = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"
    ]
    
    ALLOW_PRIVATE_NETWORKS: bool = False
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create global settings instance
settings = Settings()
