#!/usr/bin/env python3
"""
SSH PID Manager for Remote Server Process Tracking

Handles SSH connections and process monitoring without SFTP.
"""

import paramiko
import re
import time
from datetime import datetime
from typing import List, Dict, Optional, Tuple


class PIDManager:
    """Manages SSH connections and process monitoring"""
    
    def __init__(self, message_callback=None, status_callback=None):
        """Initialize PID manager with callback functions"""
        self.message_callback = message_callback or (lambda msg: print(msg))
        self.status_callback = status_callback or (lambda status: print(f"Status: {status}"))
        self.ssh = None
        self.connected = False
        self.monitored_pids = {}  # Dict to store PID info
    
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
            self.ssh.connect(hostname, username=username, password=password, timeout=30)
            self.log_message("✅ SSH Connection established successfully!")
            self.connected = True
            
            # Get basic server info
            self.update_status("Getting server information...")
            self._get_server_info()
            
            return True
            
        except Exception as e:
            self.log_message(f"❌ Connection failed: {str(e)}")
            self.connected = False
            return False
    
    def _get_server_info(self):
        """Get basic server information"""
        try:
            # Get hostname
            stdin, stdout, stderr = self.ssh.exec_command('hostname')
            hostname = stdout.read().decode().strip()
            
            # Get uptime
            stdin, stdout, stderr = self.ssh.exec_command('uptime')
            uptime = stdout.read().decode().strip()
            
            # Get current user
            stdin, stdout, stderr = self.ssh.exec_command('whoami')
            current_user = stdout.read().decode().strip()
            
            self.log_message(f"📊 Server Info:")
            self.log_message(f"   Hostname: {hostname}")
            self.log_message(f"   Current User: {current_user}")
            self.log_message(f"   Uptime: {uptime}")
            
        except Exception as e:
            self.log_message(f"⚠️ Could not get server info: {str(e)}")
    
    def get_running_processes(self, filter_user=True, search_pattern=""):
        """Get list of running processes"""
        if not self.connected:
            self.log_message("❌ Not connected to server")
            return []
        
        try:
            # Command to get process information
            if filter_user:
                cmd = "ps -u $(whoami) -o pid,ppid,%cpu,%mem,etime,cmd --no-headers"
            else:
                cmd = "ps -eo pid,ppid,user,%cpu,%mem,etime,cmd --no-headers"
            
            if search_pattern:
                cmd += f" | grep -i '{search_pattern}'"
            
            self.log_message(f"🔍 Running command: {cmd}")
            
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error:
                self.log_message(f"⚠️ Command stderr: {error}")
            
            if not output:
                self.log_message("No processes found matching criteria")
                return []
            
            processes = []
            for line in output.split('\n'):
                if line.strip():
                    parts = line.strip().split(None, 6)
                    if len(parts) >= 6:
                        process = {
                            'pid': parts[0],
                            'ppid': parts[1],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'etime': parts[4],
                            'cmd': parts[5] if len(parts) > 5 else parts[5],
                            'full_cmd': parts[6] if len(parts) > 6 else parts[5]
                        }
                        processes.append(process)
            
            self.log_message(f"📋 Found {len(processes)} processes")
            return processes
            
        except Exception as e:
            self.log_message(f"❌ Error getting processes: {str(e)}")
            return []
    
    def get_process_details(self, pid):
        """Get detailed information about a specific process"""
        if not self.connected:
            self.log_message("❌ Not connected to server")
            return None
        
        try:
            # Get detailed process info
            cmd = f"ps -p {pid} -o pid,ppid,user,%cpu,%mem,vsz,rss,tty,stat,start,etime,cmd --no-headers"
            
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            
            if not output:
                self.log_message(f"❌ Process {pid} not found")
                return None
            
            parts = output.split(None, 11)
            if len(parts) >= 11:
                details = {
                    'pid': parts[0],
                    'ppid': parts[1],
                    'user': parts[2],
                    'cpu': parts[3],
                    'mem': parts[4],
                    'vsz': parts[5],
                    'rss': parts[6],
                    'tty': parts[7],
                    'stat': parts[8],
                    'start': parts[9],
                    'etime': parts[10],
                    'cmd': parts[11] if len(parts) > 11 else "N/A"
                }
                return details
            
        except Exception as e:
            self.log_message(f"❌ Error getting process details for PID {pid}: {str(e)}")
            return None
    
    def kill_process(self, pid, force=False):
        """Kill a process by PID"""
        if not self.connected:
            self.log_message("❌ Not connected to server")
            return False
        
        try:
            signal = "KILL" if force else "TERM"
            cmd = f"kill -{signal} {pid}"
            
            self.log_message(f"🔪 Killing process {pid} with signal {signal}...")
            
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            error = stderr.read().decode().strip()
            
            if error:
                self.log_message(f"❌ Error killing process: {error}")
                return False
            
            # Wait a moment and check if process still exists
            time.sleep(1)
            details = self.get_process_details(pid)
            
            if details is None:
                self.log_message(f"✅ Process {pid} killed successfully")
                return True
            else:
                self.log_message(f"⚠️ Process {pid} may still be running")
                return False
                
        except Exception as e:
            self.log_message(f"❌ Error killing process {pid}: {str(e)}")
            return False
    
    def monitor_process(self, pid, interval=5):
        """Monitor a specific process (this would be called in a thread)"""
        if not self.connected:
            self.log_message("❌ Not connected to server")
            return
        
        try:
            self.log_message(f"👀 Starting to monitor PID {pid} (interval: {interval}s)")
            self.monitored_pids[pid] = {
                'start_time': datetime.now(),
                'last_check': datetime.now(),
                'status': 'monitoring'
            }
            
            while pid in self.monitored_pids and self.monitored_pids[pid]['status'] == 'monitoring':
                details = self.get_process_details(pid)
                
                if details:
                    self.log_message(f"📊 PID {pid}: CPU={details['cpu']}%, MEM={details['mem']}%, TIME={details['etime']}")
                    self.monitored_pids[pid]['last_check'] = datetime.now()
                else:
                    self.log_message(f"💀 Process {pid} no longer exists")
                    if pid in self.monitored_pids:
                        self.monitored_pids[pid]['status'] = 'terminated'
                    break
                
                time.sleep(interval)
                
        except Exception as e:
            self.log_message(f"❌ Error monitoring process {pid}: {str(e)}")
            if pid in self.monitored_pids:
                self.monitored_pids[pid]['status'] = 'error'
    
    def stop_monitoring(self, pid):
        """Stop monitoring a specific process"""
        if pid in self.monitored_pids:
            self.monitored_pids[pid]['status'] = 'stopped'
            self.log_message(f"⏹️ Stopped monitoring PID {pid}")
        
    def get_system_stats(self):
        """Get system statistics"""
        if not self.connected:
            self.log_message("❌ Not connected to server")
            return None
        
        try:
            stats = {}
            
            # CPU info
            stdin, stdout, stderr = self.ssh.exec_command("cat /proc/loadavg")
            loadavg = stdout.read().decode().strip()
            stats['load_average'] = loadavg
            
            # Memory info
            stdin, stdout, stderr = self.ssh.exec_command("free -h")
            memory_info = stdout.read().decode().strip()
            stats['memory'] = memory_info
            
            # Disk usage
            stdin, stdout, stderr = self.ssh.exec_command("df -h /")
            disk_info = stdout.read().decode().strip()
            stats['disk'] = disk_info
            
            # Process count
            stdin, stdout, stderr = self.ssh.exec_command("ps aux | wc -l")
            process_count = stdout.read().decode().strip()
            stats['process_count'] = process_count
            
            return stats
            
        except Exception as e:
            self.log_message(f"❌ Error getting system stats: {str(e)}")
            return None
    
    def close(self):
        """Close SSH connection"""
        if self.ssh:
            # Stop all monitoring
            for pid in list(self.monitored_pids.keys()):
                self.stop_monitoring(pid)
            
            self.ssh.close()
            self.connected = False
            self.log_message("🔌 SSH connection closed")
