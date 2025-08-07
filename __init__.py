#!/usr/bin/env python3
"""
Remote Server Log Manager

A modular GUI application for downloading and analyzing logs from remote servers.
"""

__version__ = "1.0.0"
__author__ = "Remote Server Log Manager Team"
__description__ = "GUI application for remote server log management"

# Import main classes for easy access
from .config import Config
from .ssh_manager import SSHManager
from .log_analyzer import LogAnalyzer
from .file_selector import LogFileSelector

__all__ = [
    'Config',
    'SSHManager', 
    'LogAnalyzer',
    'LogFileSelector'
]
