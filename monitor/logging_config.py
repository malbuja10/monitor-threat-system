import logging
import sys
from logging.handlers import RotatingFileHandler
import config

def get_logger(module_name: str) -> logging.Logger:
    """Configures global handlers if missing, and returns a module-specific logger."""
    root_logger = logging.getLogger()
    
    # Configure handlers only once
    if not root_logger.hasHandlers():
        # Create rotating file handler
        file_handler = RotatingFileHandler(
            config.LOG_PATH, 
            maxBytes=5 * 1024 * 1024, 
            backupCount=5
        )
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
        file_handler.setFormatter(file_formatter)
        
        # Create console stream handler
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
        stream_handler.setFormatter(stream_formatter)
        
        # Apply to root
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(stream_handler)
        
    return logging.getLogger(module_name)
