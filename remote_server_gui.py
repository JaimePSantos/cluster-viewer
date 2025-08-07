#!/usr/bin/env python3
"""
Remote Server Log Manager GUI

A GUI application for downloading and analyzing logs from remote servers.
Provides a simple interface to replicate the functionality of the get_logs.py script.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import threading
import queue
import paramiko
import os
import stat
from pathlib import Path
import getpass
from dotenv import load_dotenv
import re
from datetime import datetime, timezone, timedelta
import glob
import time

# Load environment variables from .env file
load_dotenv()

class RemoteServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Remote Server Log Manager")
        self.root.geometry("800x600")
        
        # Queue for thread communication
        self.message_queue = queue.Queue()
        
        # Server timezone info
        self.server_timezone_info = None
        
        self.setup_ui()
        self.process_queue()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Remote Server Log Manager", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Connection settings frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        conn_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        conn_frame.columnconfigure(1, weight=1)
        
        # Connection fields
        ttk.Label(conn_frame, text="Hostname:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.hostname_var = tk.StringVar(value=os.getenv('SFTP_HOSTNAME', "200.17.113.204"))
        self.hostname_entry = ttk.Entry(conn_frame, textvariable=self.hostname_var)
        self.hostname_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(conn_frame, text="Username:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.username_var = tk.StringVar(value=os.getenv('SFTP_USERNAME', "jpsantos"))
        self.username_entry = ttk.Entry(conn_frame, textvariable=self.username_var)
        self.username_entry.grid(row=0, column=3, sticky=(tk.W, tk.E))
        
        ttk.Label(conn_frame, text="Remote Path:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.remote_path_var = tk.StringVar(value=os.getenv('SFTP_REMOTE_PATH', "Documents/sqw/logs/"))
        self.remote_path_entry = ttk.Entry(conn_frame, textvariable=self.remote_path_var)
        self.remote_path_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        ttk.Label(conn_frame, text="Local Path:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.local_path_var = tk.StringVar(value=os.getenv('SFTP_LOCAL_PATH', "./logs"))
        local_path_frame = ttk.Frame(conn_frame)
        local_path_frame.grid(row=1, column=3, sticky=(tk.W, tk.E), pady=(5, 0))
        local_path_frame.columnconfigure(0, weight=1)
        
        self.local_path_entry = ttk.Entry(local_path_frame, textvariable=self.local_path_var)
        self.local_path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        browse_btn = ttk.Button(local_path_frame, text="Browse", command=self.browse_local_path)
        browse_btn.grid(row=0, column=1)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        # Main action buttons
        self.download_btn = ttk.Button(button_frame, text="Download Logs", 
                                      command=self.download_logs, style="Accent.TButton")
        self.download_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.analyze_btn = ttk.Button(button_frame, text="Analyze Logs", 
                                     command=self.analyze_logs)
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear output button
        self.clear_btn = ttk.Button(button_frame, text="Clear Output", 
                                   command=self.clear_output)
        self.clear_btn.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var)
        self.status_label.grid(row=4, column=0, columnspan=3, sticky=tk.W)
        
        # Output text area
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        output_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def browse_local_path(self):
        """Browse for local download directory"""
        directory = filedialog.askdirectory(
            title="Select Local Download Directory",
            initialdir=self.local_path_var.get()
        )
        if directory:
            self.local_path_var.set(directory)
    
    def log_message(self, message):
        """Add message to the queue for display in the GUI"""
        self.message_queue.put(("log", message))
    
    def update_status(self, status):
        """Update status message"""
        self.message_queue.put(("status", status))
    
    def set_progress(self, active):
        """Start or stop progress bar"""
        self.message_queue.put(("progress", active))
    
    def process_queue(self):
        """Process messages from worker threads"""
        try:
            while True:
                msg_type, message = self.message_queue.get_nowait()
                
                if msg_type == "log":
                    self.output_text.insert(tk.END, message + "\n")
                    self.output_text.see(tk.END)
                elif msg_type == "status":
                    self.status_var.set(message)
                elif msg_type == "progress":
                    if message:
                        self.progress.start()
                    else:
                        self.progress.stop()
                elif msg_type == "enable_buttons":
                    self.download_btn.config(state=tk.NORMAL)
                    self.analyze_btn.config(state=tk.NORMAL)
                elif msg_type == "disable_buttons":
                    self.download_btn.config(state=tk.DISABLED)
                    self.analyze_btn.config(state=tk.DISABLED)
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queue)
    
    def clear_output(self):
        """Clear the output text area"""
        self.output_text.delete(1.0, tk.END)
    
    def download_logs(self):
        """Start download logs in a separate thread"""
        # Disable buttons during operation
        self.message_queue.put(("disable_buttons", None))
        
        # Start download in separate thread
        thread = threading.Thread(target=self._download_logs_worker, daemon=True)
        thread.start()
    
    def _download_logs_worker(self):
        """Worker function for downloading logs"""
        try:
            self.set_progress(True)
            self.update_status("Connecting to server...")
            self.log_message("Starting download process...")
            
            # Get connection parameters
            hostname = self.hostname_var.get()
            username = self.username_var.get()
            remote_path = self.remote_path_var.get()
            local_path = self.local_path_var.get()
            
            # Create local directory
            Path(local_path).mkdir(parents=True, exist_ok=True)
            self.log_message(f"Created local directory: {local_path}")
            
            # Establish SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Get password
            password = os.getenv('SFTP_PASSWORD')
            if not password:
                # Use a simple dialog for password input
                password = simpledialog.askstring("Password", 
                                                f"Enter password for {username}@{hostname}:", 
                                                show='*')
                if not password:
                    self.log_message("Password input cancelled.")
                    return
            
            self.log_message(f"Connecting to {hostname}...")
            ssh.connect(hostname, username=username, password=password)
            self.log_message("Connected successfully!")
            
            # Get server timezone information
            self.update_status("Detecting server timezone...")
            self.server_timezone_info = self._get_server_timezone(ssh)
            
            # Start SFTP session
            self.update_status("Starting file transfer...")
            sftp = ssh.open_sftp()
            
            # Download files recursively
            self._download_recursive(sftp, remote_path, local_path)
            
            sftp.close()
            ssh.close()
            
            self.log_message("Download completed successfully!")
            self.update_status("Download completed")
            
        except paramiko.AuthenticationException:
            self.log_message("❌ Authentication failed. Please check your credentials.")
            self.update_status("Authentication failed")
        except Exception as e:
            self.log_message(f"❌ Error: {str(e)}")
            self.update_status("Error occurred")
        finally:
            self.set_progress(False)
            self.message_queue.put(("enable_buttons", None))
    
    def _get_server_timezone(self, ssh):
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
                    stdin, stdout, stderr = ssh.exec_command(cmd)
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
                stdin, stdout, stderr = ssh.exec_command("date '+%Y-%m-%d %H:%M:%S %Z %z'")
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
    
    def _download_recursive(self, sftp, remote_dir, local_dir):
        """Recursively download files from remote directory"""
        try:
            files = sftp.listdir_attr(remote_dir)
            
            for file_attr in files:
                remote_file = f"{remote_dir}/{file_attr.filename}"
                local_file = os.path.join(local_dir, file_attr.filename)
                
                if stat.S_ISDIR(file_attr.st_mode):
                    Path(local_file).mkdir(parents=True, exist_ok=True)
                    self.log_message(f"📁 Created directory: {local_file}")
                    self._download_recursive(sftp, remote_file, local_file)
                else:
                    sftp.get(remote_file, local_file)
                    self.log_message(f"📄 Downloaded: {file_attr.filename}")
                    
        except FileNotFoundError:
            self.log_message(f"❌ Remote directory not found: {remote_dir}")
        except Exception as e:
            self.log_message(f"❌ Error downloading {remote_dir}: {str(e)}")
    
    def analyze_logs(self):
        """Start log analysis in a separate thread"""
        # Disable buttons during operation
        self.message_queue.put(("disable_buttons", None))
        
        # Start analysis in separate thread
        thread = threading.Thread(target=self._analyze_logs_worker, daemon=True)
        thread.start()
    
    def _analyze_logs_worker(self):
        """Worker function for analyzing logs"""
        try:
            self.set_progress(True)
            self.update_status("Analyzing logs...")
            
            local_path = self.local_path_var.get()
            
            # Find all log files
            log_files = glob.glob(os.path.join(local_path, "**/*.log"), recursive=True)
            
            if not log_files:
                self.log_message("❌ No log files found to analyze")
                self.log_message(f"Searched in: {local_path}")
                return
            
            self.log_message(f"Found {len(log_files)} log file(s)")
            
            # Show log file selection dialog
            selected_files = self._show_log_selection_dialog(log_files)
            
            if not selected_files:
                self.log_message("No log files selected for analysis")
                return
            
            # Analyze selected files
            for log_file in selected_files:
                self.log_message(f"\n{'='*60}")
                self.log_message(f"Analyzing {os.path.basename(log_file)}")
                self.log_message('='*60)
                self._analyze_single_log(log_file)
            
            self.log_message("\n✅ Log analysis completed!")
            self.update_status("Analysis completed")
            
        except Exception as e:
            self.log_message(f"❌ Error during analysis: {str(e)}")
            self.update_status("Analysis error")
        finally:
            self.set_progress(False)
            self.message_queue.put(("enable_buttons", None))
    
    def _show_log_selection_dialog(self, log_files):
        """Show dialog to select which log files to analyze"""
        # Create a new window for file selection
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Log Files to Analyze")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        selected_files = []
        current_log_files = log_files.copy()  # Keep track of current file list
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Instructions and sort controls
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Select log files to analyze (organized by folder):", 
                 font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        # Sort button
        def sort_by_modified():
            nonlocal current_log_files
            # Sort by modification time (most recent first)
            try:
                current_log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                populate_tree()
            except Exception as e:
                self.log_message(f"Error sorting files: {str(e)}")
        
        sort_btn = ttk.Button(header_frame, text="Sort by Recently Modified", command=sort_by_modified)
        sort_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Expand/Collapse buttons
        expand_btn = ttk.Button(header_frame, text="Expand All", command=lambda: expand_all_folders())
        expand_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        collapse_btn = ttk.Button(header_frame, text="Collapse All", command=lambda: collapse_all_folders())
        collapse_btn.pack(side=tk.RIGHT)
        
        # TreeView with scrollbar for hierarchical display
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create TreeView with columns
        columns = ('size', 'modified')
        tree = ttk.Treeview(tree_frame, columns=columns, selectmode='extended')
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure columns
        tree.heading('#0', text='File/Folder', anchor=tk.W)
        tree.heading('size', text='Size', anchor=tk.E)
        tree.heading('modified', text='Modified', anchor=tk.CENTER)
        
        tree.column('#0', width=400, minwidth=200)
        tree.column('size', width=80, minwidth=60)
        tree.column('modified', width=140, minwidth=120)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=v_scrollbar.set)
        
        h_scrollbar = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=tree.xview)
        h_scrollbar.pack(fill=tk.X)
        tree.configure(xscrollcommand=h_scrollbar.set)
        
        # Dictionary to map tree items to file paths
        item_to_file = {}
        folder_items = {}
        
        def populate_tree():
            """Populate the tree with files organized by folder"""
            # Clear existing items
            tree.delete(*tree.get_children())
            item_to_file.clear()
            folder_items.clear()
            
            local_path = self.local_path_var.get()
            
            # Group files by directory
            folder_files = {}
            for log_file in current_log_files:
                rel_path = os.path.relpath(log_file, local_path)
                folder = os.path.dirname(rel_path) if os.path.dirname(rel_path) else "."
                
                if folder not in folder_files:
                    folder_files[folder] = []
                folder_files[folder].append(log_file)
            
            # Sort folders
            sorted_folders = sorted(folder_files.keys())
            
            file_counter = 1
            for folder in sorted_folders:
                # Create folder item
                folder_display = folder if folder != "." else "📁 Root Directory"
                if folder != ".":
                    folder_display = f"📁 {folder}"
                
                folder_item = tree.insert('', 'end', text=folder_display, open=True)
                folder_items[folder] = folder_item
                
                # Sort files in this folder by modification time if sort is active
                folder_file_list = folder_files[folder]
                
                for log_file in folder_file_list:
                    rel_path = os.path.relpath(log_file, local_path)
                    filename = os.path.basename(rel_path)
                    
                    # Get file info
                    try:
                        file_stat = os.stat(log_file)
                        mod_time = datetime.fromtimestamp(file_stat.st_mtime)
                        time_str = mod_time.strftime("%Y-%m-%d %H:%M")
                        size_str = f"{file_stat.st_size:,} B"
                    except:
                        time_str = "Unknown"
                        size_str = "Unknown"
                    
                    # Insert file item with numbering
                    file_display = f"{file_counter:3d}. 📄 {filename}"
                    file_item = tree.insert(folder_item, 'end', text=file_display, 
                                          values=(size_str, time_str))
                    
                    # Map tree item to actual file path
                    item_to_file[file_item] = log_file
                    file_counter += 1
        
        def expand_all_folders():
            """Expand all folder items"""
            for item in folder_items.values():
                tree.item(item, open=True)
        
        def collapse_all_folders():
            """Collapse all folder items"""
            for item in folder_items.values():
                tree.item(item, open=False)
        
        # Initial population
        populate_tree()
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def select_all_files():
            """Select all file items (not folders)"""
            for item in item_to_file.keys():
                tree.selection_add(item)
        
        def clear_selection():
            tree.selection_remove(tree.selection())
        
        def analyze_selected():
            selection = tree.selection()
            if selection:
                # Only include actual files (not folders)
                for item in selection:
                    if item in item_to_file:
                        selected_files.append(item_to_file[item])
            dialog.destroy()
        
        def cancel():
            dialog.destroy()
        
        # Button layout
        ttk.Button(button_frame, text="Select All Files", command=select_all_files).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Clear Selection", command=clear_selection).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Analyze Selected", command=analyze_selected).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.RIGHT)
        
        # Info label
        info_label = ttk.Label(main_frame, text=f"Found {len(current_log_files)} log files in {len(folder_items)} folders. Select files and click 'Analyze Selected' to proceed.", 
                              font=("Arial", 9), foreground="gray")
        info_label.pack(pady=(5, 0))
        
        # Instructions
        instructions_label = ttk.Label(main_frame, 
                                     text="💡 Tip: Click folder icons to expand/collapse, select individual files or use 'Select All Files'", 
                                     font=("Arial", 8), foreground="blue")
        instructions_label.pack(pady=(2, 0))
        
        # Don't auto-select all - let user choose
        
        # Wait for dialog to close
        dialog.wait_window()
        
        return selected_files
    
    def _analyze_single_log(self, log_file_path):
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
        server_offset_hours = self._calculate_timezone_offset(download_time, last_time)
        
        if server_offset_hours is None:
            # Ask user for timezone offset
            offset_str = simpledialog.askstring(
                "Timezone Offset",
                f"Enter timezone offset from server to local time (hours):\n"
                f"Your local time: {download_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Last heartbeat: {last_time.strftime('%Y-%m-%d %H:%M:%S')} (server time)\n"
                f"Example: -3, 0, +2 (or leave empty for 0)",
                initialvalue="0"
            )
            
            try:
                server_offset_hours = float(offset_str) if offset_str else 0
            except (ValueError, TypeError):
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
    
    def _calculate_timezone_offset(self, local_time, server_log_time):
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


def main():
    """Main function to run the GUI application"""
    root = tk.Tk()
    
    # Set up modern styling
    style = ttk.Style()
    
    # Try to use a modern theme
    available_themes = style.theme_names()
    if 'clam' in available_themes:
        style.theme_use('clam')
    elif 'alt' in available_themes:
        style.theme_use('alt')
    
    # Create and run the application
    app = RemoteServerGUI(root)
    
    # Handle window closing
    def on_closing():
        root.quit()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")


if __name__ == "__main__":
    main()
