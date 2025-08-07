#!/usr/bin/env python3
"""
Configuration module for Remote Server Log Manager

Handles environment variables and application settings.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration class"""
    
    # Default connection settings
    DEFAULT_HOSTNAME = "200.17.113.204"
    DEFAULT_USERNAME = "jpsantos"
    DEFAULT_REMOTE_PATH = "Documents/sqw/logs/"
    DEFAULT_LOCAL_PATH = "./logs"
    
    # UI settings
    WINDOW_TITLE = "Remote Server Log Manager"
    WINDOW_GEOMETRY = "800x600"
    FONT_TITLE = ("Arial", 16, "bold")
    FONT_LABEL = ("Arial", 12, "bold")
    FONT_INFO = ("Arial", 9)
    FONT_TIPS = ("Arial", 8)
    
    # Colors
    COLOR_GRAY = "gray"
    COLOR_BLUE = "blue"
    
    # Progress and threading
    QUEUE_CHECK_INTERVAL = 100  # milliseconds
    
    @classmethod
    def get_hostname(cls):
        """Get hostname from environment or default"""
        return os.getenv('SFTP_HOSTNAME', cls.DEFAULT_HOSTNAME)
    
    @classmethod
    def get_username(cls):
        """Get username from environment or default"""
        return os.getenv('SFTP_USERNAME', cls.DEFAULT_USERNAME)
    
    @classmethod
    def get_remote_path(cls):
        """Get remote path from environment or default"""
        return os.getenv('SFTP_REMOTE_PATH', cls.DEFAULT_REMOTE_PATH)
    
    @classmethod
    def get_local_path(cls):
        """Get local path from environment or default"""
        return os.getenv('SFTP_LOCAL_PATH', cls.DEFAULT_LOCAL_PATH)
    
    @classmethod
    def get_password(cls):
        """Get password from environment"""
        return os.getenv('SFTP_PASSWORD')
