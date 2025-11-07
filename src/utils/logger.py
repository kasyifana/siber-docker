# src/utils/logger.py

import sys
from loguru import logger
from pathlib import Path
from typing import Optional

def setup_logger(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: str = "text"
):
    """
    Setup application logger
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        log_format: Format type (text or json)
    """
    
    # Remove default logger
    logger.remove()
    
    # Define format based on type
    if log_format == "json":
        format_string = "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message} | {extra}"
        serialize = True
    else:
        format_string = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        )
        serialize = False
    
    # Add console handler
    logger.add(
        sys.stderr,
        format=format_string,
        level=log_level,
        colorize=True if log_format == "text" else False,
        serialize=serialize
    )
    
    # Add file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.add(
            log_file,
            format=format_string,
            level=log_level,
            rotation="10 MB",
            retention="7 days",
            compression="zip",
            serialize=serialize
        )
    
    logger.info(f"Logger initialized with level {log_level}")

def get_logger():
    """Get the application logger"""
    return logger
