#!/usr/bin/env python3
"""
SSH/SFTP utilities for Remote Server Log Manager

Handles all remote server connection and file transfer operations.
"""

import paramiko
import os
import stat
import time
from pathlib import Path
from datetime import datetime, timedelta


class SSHManager:
    """Manages SSH connections and operations"""
    
    def __init__(self, message_callback=None, status_callback=None):
        """Initialize SSH manager with callback functions"""
        self.message_callback = message_callback or (lambda msg: print(msg))
        self.status_callback = status_callback or (lambda status: print(f"Status: {status}"))
        self.ssh = None
        self.sftp = None
        self.server_timezone_info = None
    
    def log_message(self, message):
        """Log a message using the callback"""
        self.message_callback(message)
    
    def update_status(self, status):
        """Update status using the callback"""
        self.status_callback(status)
    
    def connect(self, hostname, username, password):
        """Establish SSH connection"""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.log_message(f"Connecting to {hostname}...")
            self.ssh.connect(hostname, username=username, password=password)
            self.log_message("Connected successfully!")
            
            # Get server timezone information
            self.update_status("Detecting server timezone...")
            self.server_timezone_info = self._get_server_timezone()
            
            return True
            
        except paramiko.AuthenticationException:
            self.log_message("❌ Authentication failed. Please check your credentials.")
            return False
        except Exception as e:
            self.log_message(f"❌ Connection error: {str(e)}")
            return False
    
    def start_sftp(self):
        """Start SFTP session"""
        if not self.ssh:
            raise Exception("SSH connection not established")
        
        self.update_status("Starting file transfer...")
        self.sftp = self.ssh.open_sftp()
        return self.sftp
    
    def download_files(self, remote_path, local_path):
        """Download files recursively from remote directory"""
        if not self.sftp:
            self.start_sftp()
        
        # Create local directory
        Path(local_path).mkdir(parents=True, exist_ok=True)
        self.log_message(f"Created local directory: {local_path}")
        
        # Download files recursively
        self._download_recursive(remote_path, local_path)
    
    def _download_recursive(self, remote_dir, local_dir):
        """Recursively download files from remote directory"""
        try:
            files = self.sftp.listdir_attr(remote_dir)
            
            for file_attr in files:
                remote_file = f"{remote_dir}/{file_attr.filename}"
                local_file = os.path.join(local_dir, file_attr.filename)
                
                if stat.S_ISDIR(file_attr.st_mode):
                    Path(local_file).mkdir(parents=True, exist_ok=True)
                    self.log_message(f"📁 Created directory: {local_file}")
                    self._download_recursive(remote_file, local_file)
                else:
                    self.sftp.get(remote_file, local_file)
                    self.log_message(f"📄 Downloaded: {file_attr.filename}")
                    
        except FileNotFoundError:
            self.log_message(f"❌ Remote directory not found: {remote_dir}")
        except Exception as e:
            self.log_message(f"❌ Error downloading {remote_dir}: {str(e)}")
    
    def _get_server_timezone(self):
        """Get server timezone information via SSH"""
        try:
            self.log_message("Detecting server timezone...")
            
            timezone_commands = [
                "timedatectl show --property=Timezone --value",
                "cat /etc/timezone",
                r"readlink /etc/localtime | sed 's/.*zoneinfo\///'",
                "date +%Z",
                "date +%z"
            ]
            
            server_tz_info = {}
            
            for cmd in timezone_commands:
                try:
                    stdin, stdout, stderr = self.ssh.exec_command(cmd)
                    output = stdout.read().decode().strip()
                    if output and not stderr.read():
                        if "timedatectl" in cmd:
                            server_tz_info['timezone'] = output
                        elif "/etc/timezone" in cmd:
                            server_tz_info['timezone'] = output
                        elif "readlink" in cmd:
                            server_tz_info['timezone'] = output
                        elif "+%Z" in cmd:
                            server_tz_info['tz_abbrev'] = output
                        elif "+%z" in cmd:
                            server_tz_info['utc_offset'] = output
                        break
                except:
                    continue
            
            # Get current server time
            try:
                stdin, stdout, stderr = self.ssh.exec_command("date '+%Y-%m-%d %H:%M:%S %Z %z'")
                server_time_output = stdout.read().decode().strip()
                if server_time_output:
                    server_tz_info['current_time'] = server_time_output
            except:
                pass
            
            if server_tz_info:
                self.log_message(f"Server timezone detected: {server_tz_info}")
                return server_tz_info
            else:
                self.log_message("Could not detect server timezone automatically")
                return None
                
        except Exception as e:
            self.log_message(f"Error detecting server timezone: {str(e)}")
            return None
    
    def calculate_timezone_offset(self, local_time, server_log_time):
        """Calculate timezone offset between server and local machine"""
        if not self.server_timezone_info:
            return None
        
        try:
            # Parse UTC offset directly (e.g., "+0100", "-0500")
            if 'utc_offset' in self.server_timezone_info:
                utc_offset_str = self.server_timezone_info['utc_offset']
                if len(utc_offset_str) == 5 and (utc_offset_str[0] in ['+', '-']):
                    sign = 1 if utc_offset_str[0] == '+' else -1
                    hours = int(utc_offset_str[1:3])
                    minutes = int(utc_offset_str[3:5])
                    server_utc_offset = sign * (hours + minutes / 60.0)
                    
                    # Get local UTC offset
                    local_utc_offset = -time.timezone / 3600.0
                    if time.daylight and time.localtime().tm_isdst:
                        local_utc_offset += 1
                    
                    offset = local_utc_offset - server_utc_offset
                    self.log_message(f"Auto-detected timezone offset: {offset:+.1f}h")
                    return offset
            
            # Check if server is UTC
            if 'timezone' in self.server_timezone_info:
                server_tz = self.server_timezone_info['timezone']
                if server_tz in ['UTC', 'Etc/UTC', 'GMT']:
                    local_utc_offset = -time.timezone / 3600.0
                    if time.daylight and time.localtime().tm_isdst:
                        local_utc_offset += 1
                    
                    self.log_message(f"Server is UTC, local offset: {local_utc_offset:+.1f}h")
                    return local_utc_offset
            
            return None
            
        except Exception as e:
            self.log_message(f"Error calculating timezone offset: {str(e)}")
            return None
    
    def close(self):
        """Close SSH and SFTP connections"""
        if self.sftp:
            self.sftp.close()
            self.sftp = None
        
        if self.ssh:
            self.ssh.close()
            self.ssh = None
