#!/usr/bin/env python3
"""
Log analysis utilities for Remote Server Log Manager

Handles parsing and analysis of log files.
"""

import re
import os
import glob
import time
from datetime import datetime, timedelta


class LogAnalyzer:
    """Handles log file analysis operations"""
    
    def __init__(self, message_callback=None, status_callback=None, ssh_manager=None):
        """Initialize log analyzer with callback functions"""
        self.message_callback = message_callback or (lambda msg: print(msg))
        self.status_callback = status_callback or (lambda status: print(f"Status: {status}"))
        self.ssh_manager = ssh_manager
    
    def log_message(self, message):
        """Log a message using the callback"""
        self.message_callback(message)
    
    def update_status(self, status):
        """Update status using the callback"""
        self.status_callback(status)
    
    def find_log_files(self, local_path):
        """Find all log files in the local directory"""
        log_files = glob.glob(os.path.join(local_path, "**/*.log"), recursive=True)
        return log_files
    
    def analyze_log_files(self, log_files):
        """Analyze multiple log files"""
        if not log_files:
            self.log_message("❌ No log files found to analyze")
            return
        
        self.log_message(f"Found {len(log_files)} log file(s)")
        
        # Analyze each file
        for log_file in log_files:
            self.log_message(f"\n{'='*60}")
            self.log_message(f"Analyzing {os.path.basename(log_file)}")
            self.log_message('='*60)
            self.analyze_single_log(log_file)
    
    def analyze_single_log(self, log_file_path):
        """Analyze a single log file for heartbeat information"""
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract heartbeat interval
            interval_match = re.search(r'Heartbeat interval: ([\d.]+)s', content)
            if not interval_match:
                self.log_message("❌ Could not find heartbeat interval in log")
                return
            
            heartbeat_interval = float(interval_match.group(1))
            self.log_message(f"💓 Heartbeat interval: {heartbeat_interval}s")
            
            # Find all heartbeats
            heartbeat_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - INFO - HEARTBEAT #(\d+) - Elapsed: ([\d.]+)s'
            heartbeats = re.findall(heartbeat_pattern, content)
            
            if not heartbeats:
                self.log_message("❌ No heartbeats found in log")
                return
            
            self.log_message(f"Found {len(heartbeats)} heartbeats in log")
            
            # Parse timestamps and find the range
            first_heartbeat = heartbeats[0]
            last_heartbeat = heartbeats[-1]
            
            first_time = datetime.strptime(first_heartbeat[0], "%Y-%m-%d %H:%M:%S,%f")
            last_time = datetime.strptime(last_heartbeat[0], "%Y-%m-%d %H:%M:%S,%f")
            
            self.log_message(f"⏰ First heartbeat: {first_time} (#{first_heartbeat[1]})")
            self.log_message(f"⏰ Last heartbeat:  {last_time} (#{last_heartbeat[1]})")
            
            # Calculate time difference
            time_diff = last_time - first_time
            total_seconds = time_diff.total_seconds()
            
            self.log_message(f"📏 Time span: {total_seconds:.1f} seconds ({total_seconds/3600:.2f} hours)")
            
            # Calculate expected heartbeats
            expected_heartbeats = 1 + int(total_seconds / heartbeat_interval)
            actual_heartbeats = len(heartbeats)
            
            self.log_message(f"📊 Expected heartbeats: {expected_heartbeats}")
            self.log_message(f"📊 Actual heartbeats:   {actual_heartbeats}")
            
            if actual_heartbeats < expected_heartbeats:
                missing = expected_heartbeats - actual_heartbeats
                self.log_message(f"⚠️  Missing {missing} heartbeat(s)")
            elif actual_heartbeats > expected_heartbeats:
                extra = actual_heartbeats - expected_heartbeats
                self.log_message(f"ℹ️  {extra} extra heartbeat(s) (normal variation)")
            else:
                self.log_message("✅ Heartbeat count matches expectation")
            
            # Check for gaps in heartbeat sequence
            heartbeat_numbers = [int(hb[1]) for hb in heartbeats]
            expected_sequence = list(range(1, len(heartbeats) + 1))
            
            if heartbeat_numbers != expected_sequence:
                self.log_message("⚠️  Heartbeat sequence has gaps or duplicates")
                missing_numbers = set(expected_sequence) - set(heartbeat_numbers)
                if missing_numbers:
                    self.log_message(f"   Missing heartbeat numbers: {sorted(missing_numbers)}")
            else:
                self.log_message("✅ Heartbeat sequence is continuous")
            
            # Current status analysis
            self._analyze_current_status(last_time, heartbeat_interval)
            
        except Exception as e:
            self.log_message(f"❌ Error analyzing log file: {str(e)}")
    
    def _analyze_current_status(self, last_time, heartbeat_interval):
        """Analyze current status based on last heartbeat"""
        download_time = datetime.now()
        
        # Calculate timezone offset
        server_offset_hours = None
        if self.ssh_manager:
            server_offset_hours = self.ssh_manager.calculate_timezone_offset(download_time, last_time)
        
        if server_offset_hours is None:
            # Default to no offset if we can't calculate it
            server_offset_hours = 0
            self.log_message("Using no timezone offset (assuming same timezone)")
        
        # Calculate adjusted server time
        adjusted_last_time = last_time + timedelta(hours=server_offset_hours)
        time_since_last = download_time - adjusted_last_time
        seconds_since_last = time_since_last.total_seconds()
        
        self.log_message(f"\n🌍 Timezone Analysis:")
        if server_offset_hours != 0:
            self.log_message(f"   Timezone offset: {server_offset_hours:+.1f} hours")
        self.log_message(f"   Last heartbeat (local time): {adjusted_last_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.log_message(f"   Current local time: {download_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.log_message(f"   Time since last heartbeat: {seconds_since_last:.1f} seconds ({seconds_since_last/60:.1f} minutes)")
        
        # Status assessment
        if seconds_since_last > heartbeat_interval * 2:
            self.log_message("⚠️  Process may have stopped (no heartbeat for >2 intervals)")
        elif seconds_since_last > heartbeat_interval * 1.5:
            self.log_message("⚠️  Process may be delayed (no heartbeat for >1.5 intervals)")
        else:
            self.log_message("✅ Process appears to be running normally")
