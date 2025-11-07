# src/health.py

"""
Health check endpoint for monitoring
"""

from datetime import datetime
from typing import Dict
import asyncio

class HealthCheck:
    """Health check utilities"""
    
    def __init__(self):
        self.start_time = datetime.now()
    
    async def check(self) -> Dict:
        """
        Perform health check
        
        Returns:
            Health status dictionary
        """
        return {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': (datetime.now() - self.start_time).total_seconds(),
            'services': {
                'mcp_server': 'running',
                'tools': 'ready'
            }
        }
    
    def get_uptime(self) -> str:
        """Get uptime as human-readable string"""
        uptime = datetime.now() - self.start_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        
        return " ".join(parts)
