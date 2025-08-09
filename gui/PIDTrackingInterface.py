#!/usr/bin/env python3
"""
SSH PID Tracking GUI Interface

GUI for tracking and managing remote server processes via SSH.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import threading
import queue
from datetime import datetime

from core.config import Config
from core.pid_manager import PIDManager


class PIDTrackingInterface:
    """PID tracking GUI interface"""
    
    def __init__(self, parent_frame, message_queue):
        """Initialize the PID tracking interface"""
        self.parent_frame = parent_frame
        self.message_queue = message_queue
        
        # Initialize PID manager
        self.pid_manager = PIDManager(
            message_callback=self.log_message,
            status_callback=self.update_status
        )
        
        # Connection states
        self.subhost_connected = False
        
        # Monitoring state
        self.monitoring_threads = {}
        self.auto_refresh = False
        self.refresh_interval = 10  # seconds
        
        # Setup UI
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame with padding
        main_frame = ttk.Frame(self.parent_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Setup individual sections
        self._setup_title(main_frame)
        self._setup_connection_settings(main_frame)
        self._setup_process_controls(main_frame)
        self._setup_process_list(main_frame)
        self._setup_output_area(main_frame)
    
    def _setup_title(self, parent):
        """Setup the title section"""
        title_label = ttk.Label(parent, text="SSH Process Manager", 
                               font=Config.FONT_TITLE)
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
    
    def _setup_connection_settings(self, parent):
        """Setup the connection settings section"""
        conn_frame = ttk.LabelFrame(parent, text="SSH Connection", padding="10")
        conn_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        conn_frame.columnconfigure(1, weight=1)
        
        # Connection fields
        self._setup_connection_fields(conn_frame)
        
        # Subhost settings
        self._setup_subhost_settings(conn_frame)
    
    def _setup_connection_fields(self, parent):
        """Setup individual connection fields"""
        # Hostname and Username row
        ttk.Label(parent, text="Hostname:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.hostname_var = tk.StringVar(value=Config.get_hostname())
        self.hostname_entry = ttk.Entry(parent, textvariable=self.hostname_var)
        self.hostname_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(parent, text="Username:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.username_var = tk.StringVar(value=Config.get_username())
        self.username_entry = ttk.Entry(parent, textvariable=self.username_var)
        self.username_entry.grid(row=0, column=3, sticky=(tk.W, tk.E))
        
        # Connection button
        self.connect_btn = ttk.Button(parent, text="Connect", 
                                     command=self.connect_ssh, style="Accent.TButton")
        self.connect_btn.grid(row=0, column=4, padx=(10, 0))
        
        self.disconnect_btn = ttk.Button(parent, text="Disconnect", 
                                        command=self.disconnect_ssh, state=tk.DISABLED)
        self.disconnect_btn.grid(row=0, column=5, padx=(5, 0))
    
    def _setup_subhost_settings(self, parent):
        """Setup the subhost connection settings"""
        # Separator
        ttk.Separator(parent, orient='horizontal').grid(row=1, column=0, columnspan=6, sticky=(tk.W, tk.E), pady=(10, 10))
        
        # Subhost section label
        subhost_label = ttk.Label(parent, text="Subhost Connection (via main host)", font=("Arial", 10, "bold"))
        subhost_label.grid(row=2, column=0, columnspan=6, sticky=tk.W, pady=(0, 5))
        
        # Subhost hostname row
        ttk.Label(parent, text="Subhost:").grid(row=3, column=0, sticky=tk.W, padx=(0, 5))
        self.subhost_hostname_var = tk.StringVar(value=Config.get_subhost_hostname())
        self.subhost_hostname_entry = ttk.Entry(parent, textvariable=self.subhost_hostname_var, width=15)
        self.subhost_hostname_entry.grid(row=3, column=1, sticky=tk.W, padx=(0, 10))
        
        # Note about connection
        note_label = ttk.Label(parent, text="(Connect to main host first)", font=("Arial", 8), foreground="gray")
        note_label.grid(row=3, column=2, sticky=tk.W, padx=(0, 10))
        
        # Test subhost button
        self.test_subhost_btn = ttk.Button(parent, text="Test Subhost", 
                                         command=self.test_subhost, state=tk.DISABLED)
        self.test_subhost_btn.grid(row=3, column=3, padx=(5, 5))
        
        # Subhost connect/disconnect buttons
        self.subhost_connect_btn = ttk.Button(parent, text="Connect to Subhost", 
                                            command=self.connect_subhost, state=tk.DISABLED)
        self.subhost_connect_btn.grid(row=3, column=4, padx=(10, 5))
        
        self.subhost_disconnect_btn = ttk.Button(parent, text="Disconnect", 
                                               command=self.disconnect_subhost, state=tk.DISABLED)
        self.subhost_disconnect_btn.grid(row=3, column=5, padx=(5, 0))
    
    def _setup_process_controls(self, parent):
        """Setup process control buttons and options"""
        control_frame = ttk.LabelFrame(parent, text="Process Controls", padding="10")
        control_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Buttons frame
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.list_processes_btn = ttk.Button(btn_frame, text="List Processes", 
                                           command=self.list_processes, state=tk.DISABLED)
        self.list_processes_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.system_stats_btn = ttk.Button(btn_frame, text="System Stats", 
                                         command=self.show_system_stats, state=tk.DISABLED)
        self.system_stats_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.kill_process_btn = ttk.Button(btn_frame, text="Kill Selected", 
                                         command=self.kill_selected_process, state=tk.DISABLED)
        self.kill_process_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.monitor_btn = ttk.Button(btn_frame, text="Monitor Selected", 
                                    command=self.monitor_selected_process, state=tk.DISABLED)
        self.monitor_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Options frame
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X)
        
        # Filter options
        ttk.Label(options_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.filter_user_var = tk.BooleanVar(value=True)
        self.filter_user_cb = ttk.Checkbutton(options_frame, text="My processes only", 
                                             variable=self.filter_user_var)
        self.filter_user_cb.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(options_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(options_frame, textvariable=self.search_var, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Auto-refresh
        self.auto_refresh_var = tk.BooleanVar()
        self.auto_refresh_cb = ttk.Checkbutton(options_frame, text="Auto-refresh (10s)", 
                                             variable=self.auto_refresh_var,
                                             command=self.toggle_auto_refresh)
        self.auto_refresh_cb.pack(side=tk.LEFT)
    
    def _setup_process_list(self, parent):
        """Setup the process list display"""
        list_frame = ttk.LabelFrame(parent, text="Running Processes", padding="5")
        list_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Create treeview for process list
        columns = ('PID', 'PPID', 'CPU%', 'MEM%', 'TIME', 'COMMAND')
        self.process_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        for col in columns:
            self.process_tree.heading(col, text=col)
            if col == 'COMMAND':
                self.process_tree.column(col, width=300, minwidth=200)
            elif col in ['PID', 'PPID']:
                self.process_tree.column(col, width=60, minwidth=50)
            else:
                self.process_tree.column(col, width=80, minwidth=60)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.process_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Bind double-click to show process details
        self.process_tree.bind('<Double-1>', self.show_process_details)
    
    def _setup_output_area(self, parent):
        """Setup the output text area"""
        output_frame = ttk.LabelFrame(parent, text="Output", padding="5")
        output_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=10)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Clear button
        clear_btn = ttk.Button(output_frame, text="Clear", command=self.clear_output)
        clear_btn.grid(row=1, column=0, sticky=tk.E, pady=(5, 0))
    
    def log_message(self, message):
        """Add message to the queue for display in the GUI"""
        self.message_queue.put(("log", message))
    
    def update_status(self, status):
        """Update status message"""
        self.message_queue.put(("status", status))
    
    def clear_output(self):
        """Clear the output text area"""
        self.output_text.delete(1.0, tk.END)
    
    def connect_ssh(self):
        """Connect to SSH server"""
        thread = threading.Thread(target=self._connect_ssh_worker, daemon=True)
        thread.start()
    
    def _connect_ssh_worker(self):
        """Worker function for SSH connection"""
        try:
            hostname = self.hostname_var.get()
            username = self.username_var.get()
            
            if not hostname or not username:
                self.log_message("❌ Please enter hostname and username")
                return
            
            # Get password
            password = Config.get_password()
            if not password:
                password = simpledialog.askstring("Password", 
                                                f"Enter password for {username}@{hostname}:", 
                                                show='*')
                if not password:
                    self.log_message("Password input cancelled.")
                    return
            
            # Connect
            if self.pid_manager.connect(hostname, username, password):
                self.message_queue.put(("ssh_connected", None))
            
        except Exception as e:
            self.log_message(f"❌ Connection error: {str(e)}")
    
    def disconnect_ssh(self):
        """Disconnect from SSH server"""
        self.pid_manager.close()
        self.message_queue.put(("ssh_disconnected", None))
        self.log_message("Disconnected from SSH server")
    
    def connect_subhost(self):
        """Connect to subhost via SSH command through main host"""
        if not self.pid_manager.connected:
            self.log_message("❌ Please connect to main host first")
            return
            
        thread = threading.Thread(target=self._connect_subhost_worker, daemon=True)
        thread.start()
    
    def _connect_subhost_worker(self):
        """Worker function for subhost SSH connection"""
        try:
            hostname = self.subhost_hostname_var.get()
            
            if not hostname:
                self.log_message("❌ Please enter subhost hostname")
                return
            
            # Get password for subhost
            password = simpledialog.askstring("Subhost Password", 
                                            f"Enter password for subhost {hostname}:", 
                                            show='*')
            if not password:
                self.log_message("Password input cancelled.")
                return
            
            # Test SSH connection to subhost through main host
            self.log_message(f"🔄 Testing connection to subhost {hostname}...")
            self.update_status(f"Connecting to subhost {hostname}...")
            
            # First, check if sshpass is available
            try:
                stdin, stdout, stderr = self.pid_manager.ssh.exec_command("which sshpass")
                sshpass_available = bool(stdout.read().decode().strip())
            except:
                sshpass_available = False
                self.log_message("⚠️ Could not check for sshpass availability")
            
            if sshpass_available:
                # Use sshpass if available
                test_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {hostname} 'echo \"Connection successful\" && hostname'"
            else:
                # Use expect-like approach or simple SSH test
                test_cmd = f"timeout 10 ssh -o StrictHostKeyChecking=no -o BatchMode=no {hostname} 'echo \"Connection successful\" && hostname'"
                self.log_message("⚠️ sshpass not available, using interactive SSH (may require manual password entry)")
            
            stdin, stdout, stderr = self.pid_manager.ssh.exec_command(test_cmd)
            
            if not sshpass_available:
                # For interactive SSH, send password to stdin
                stdin.write(f"{password}\n")
                stdin.flush()
            
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if "Connection successful" in output or "Connection refused" not in error:
                self.subhost_connected = True
                self.subhost_password = password  # Store password for subsequent commands
                self.subhost_hostname = hostname  # Store hostname
                subhost_hostname = output.split('\n')[-1] if '\n' in output else hostname
                self.log_message(f"✅ Connected to subhost: {subhost_hostname}")
                self.update_status(f"Connected to subhost: {subhost_hostname}")
                self.message_queue.put(("subhost_connected", None))
            else:
                self.log_message(f"❌ Failed to connect to subhost: {hostname}")
                if error:
                    self.log_message(f"Error: {error}")
                self.update_status("Subhost connection failed")
            
        except Exception as e:
            self.log_message(f"❌ Subhost connection error: {str(e)}")
            self.update_status("Subhost connection error")
    
    def disconnect_subhost(self):
        """Disconnect from subhost"""
        try:
            if hasattr(self, 'subhost_password'):
                delattr(self, 'subhost_password')
            if hasattr(self, 'subhost_hostname'):
                delattr(self, 'subhost_hostname')
            self.subhost_connected = False
            self.log_message("🔌 Disconnected from subhost")
            self.update_status("Subhost disconnected")
            self.message_queue.put(("subhost_disconnected", None))
        except Exception as e:
            self.log_message(f"❌ Error disconnecting from subhost: {str(e)}")
            self.update_status("Subhost disconnect error")
    
    def execute_subhost_command(self, command):
        """Execute a command on the subhost via SSH hop"""
        if not self.subhost_connected or not hasattr(self, 'subhost_password') or not hasattr(self, 'subhost_hostname'):
            self.log_message("❌ Not connected to subhost")
            return None, "Not connected to subhost"
        
        try:
            # Check if sshpass is available
            try:
                stdin, stdout, stderr = self.pid_manager.ssh.exec_command("which sshpass")
                sshpass_available = bool(stdout.read().decode().strip())
            except:
                sshpass_available = False
            
            if sshpass_available:
                # Use sshpass for automatic password authentication
                ssh_cmd = f"sshpass -p '{self.subhost_password}' ssh -o StrictHostKeyChecking=no {self.subhost_hostname} '{command}'"
            else:
                # Fallback to regular SSH (may not work for complex commands)
                ssh_cmd = f"ssh -o StrictHostKeyChecking=no {self.subhost_hostname} '{command}'"
                self.log_message("⚠️ sshpass not available, SSH may require manual authentication")
            
            stdin, stdout, stderr = self.pid_manager.ssh.exec_command(ssh_cmd)
            
            if not sshpass_available:
                # For interactive SSH, send password to stdin
                stdin.write(f"{self.subhost_password}\n")
                stdin.flush()
            
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            return output, error
            
        except Exception as e:
            error_msg = f"Error executing subhost command: {str(e)}"
            self.log_message(f"❌ {error_msg}")
            return None, error_msg
    
    def test_subhost(self):
        """Test subhost connection with a simple command"""
        if not self.subhost_connected:
            self.log_message("❌ Not connected to subhost")
            return
            
        thread = threading.Thread(target=self._test_subhost_worker, daemon=True)
        thread.start()
    
    def _test_subhost_worker(self):
        """Worker function to test subhost with basic commands"""
        try:
            self.log_message("🔄 Testing subhost connection...")
            
            # Test basic commands
            commands = [
                ("hostname", "Hostname"),
                ("whoami", "Current User"), 
                ("uptime", "Uptime"),
                ("pwd", "Working Directory")
            ]
            
            for cmd, description in commands:
                output, error = self.execute_subhost_command(cmd)
                if output:
                    self.log_message(f"📋 {description}: {output}")
                elif error:
                    self.log_message(f"❌ {description} error: {error}")
                    
            self.log_message("✅ Subhost test completed")
            
        except Exception as e:
            self.log_message(f"❌ Subhost test error: {str(e)}")
    
    def list_processes(self):
        """List running processes"""
        thread = threading.Thread(target=self._list_processes_worker, daemon=True)
        thread.start()
    
    def _list_processes_worker(self):
        """Worker function for listing processes"""
        try:
            filter_user = self.filter_user_var.get()
            search_pattern = self.search_var.get().strip()
            
            processes = self.pid_manager.get_running_processes(filter_user, search_pattern)
            self.message_queue.put(("update_process_list", processes))
            
        except Exception as e:
            self.log_message(f"❌ Error listing processes: {str(e)}")
    
    def show_system_stats(self):
        """Show system statistics"""
        thread = threading.Thread(target=self._show_system_stats_worker, daemon=True)
        thread.start()
    
    def _show_system_stats_worker(self):
        """Worker function for system stats"""
        try:
            stats = self.pid_manager.get_system_stats()
            if stats:
                self.log_message("\n📊 System Statistics:")
                self.log_message(f"Load Average: {stats.get('load_average', 'N/A')}")
                self.log_message("Memory Usage:")
                for line in stats.get('memory', '').split('\n'):
                    if line.strip():
                        self.log_message(f"  {line}")
                self.log_message("Disk Usage:")
                for line in stats.get('disk', '').split('\n'):
                    if line.strip():
                        self.log_message(f"  {line}")
                self.log_message(f"Total Processes: {stats.get('process_count', 'N/A')}")
                
        except Exception as e:
            self.log_message(f"❌ Error getting system stats: {str(e)}")
    
    def kill_selected_process(self):
        """Kill the selected process"""
        selected = self.process_tree.selection()
        if not selected:
            self.log_message("❌ Please select a process to kill")
            return
        
        item = self.process_tree.item(selected[0])
        pid = item['values'][0]
        cmd = item['values'][5]
        
        # Confirm action
        result = messagebox.askyesno("Confirm Kill Process", 
                                   f"Are you sure you want to kill process {pid}?\n\nCommand: {cmd}")
        if result:
            thread = threading.Thread(target=self._kill_process_worker, args=(pid,), daemon=True)
            thread.start()
    
    def _kill_process_worker(self, pid):
        """Worker function for killing process"""
        try:
            success = self.pid_manager.kill_process(pid)
            if success:
                # Refresh process list
                self._list_processes_worker()
        except Exception as e:
            self.log_message(f"❌ Error killing process: {str(e)}")
    
    def monitor_selected_process(self):
        """Start monitoring the selected process"""
        selected = self.process_tree.selection()
        if not selected:
            self.log_message("❌ Please select a process to monitor")
            return
        
        item = self.process_tree.item(selected[0])
        pid = item['values'][0]
        
        # Start monitoring in a separate thread
        if pid not in self.monitoring_threads:
            thread = threading.Thread(target=self._monitor_process_worker, args=(pid,), daemon=True)
            self.monitoring_threads[pid] = thread
            thread.start()
            self.log_message(f"Started monitoring PID {pid}")
        else:
            self.log_message(f"Already monitoring PID {pid}")
    
    def _monitor_process_worker(self, pid):
        """Worker function for monitoring process"""
        try:
            self.pid_manager.monitor_process(pid, interval=5)
        except Exception as e:
            self.log_message(f"❌ Error monitoring process {pid}: {str(e)}")
        finally:
            if pid in self.monitoring_threads:
                del self.monitoring_threads[pid]
    
    def show_process_details(self, event):
        """Show detailed information about the selected process"""
        selected = self.process_tree.selection()
        if not selected:
            return
        
        item = self.process_tree.item(selected[0])
        pid = item['values'][0]
        
        thread = threading.Thread(target=self._show_process_details_worker, args=(pid,), daemon=True)
        thread.start()
    
    def _show_process_details_worker(self, pid):
        """Worker function for showing process details"""
        try:
            details = self.pid_manager.get_process_details(pid)
            if details:
                self.log_message(f"\n🔍 Process Details for PID {pid}:")
                for key, value in details.items():
                    self.log_message(f"  {key.upper()}: {value}")
        except Exception as e:
            self.log_message(f"❌ Error getting process details: {str(e)}")
    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh of process list"""
        self.auto_refresh = self.auto_refresh_var.get()
        if self.auto_refresh:
            self._start_auto_refresh()
        
    def _start_auto_refresh(self):
        """Start auto-refresh timer"""
        if self.auto_refresh and self.pid_manager.connected:
            self._list_processes_worker()
            # Schedule next refresh
            self.parent_frame.after(self.refresh_interval * 1000, self._start_auto_refresh)
    
    def update_process_list(self, processes):
        """Update the process list in the GUI"""
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Add new processes
        for process in processes:
            self.process_tree.insert('', 'end', values=(
                process['pid'],
                process['ppid'],
                process['cpu'],
                process['mem'],
                process['etime'],
                process['cmd'][:100] + '...' if len(process['cmd']) > 100 else process['cmd']
            ))
    
    def set_connected_state(self, connected):
        """Update UI based on connection state"""
        if connected:
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.list_processes_btn.config(state=tk.NORMAL)
            self.system_stats_btn.config(state=tk.NORMAL)
            self.kill_process_btn.config(state=tk.NORMAL)
            self.monitor_btn.config(state=tk.NORMAL)
            # Enable subhost connection when main host is connected
            self.subhost_connect_btn.config(state=tk.NORMAL)
        else:
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.list_processes_btn.config(state=tk.DISABLED)
            self.system_stats_btn.config(state=tk.DISABLED)
            self.kill_process_btn.config(state=tk.DISABLED)
            self.monitor_btn.config(state=tk.DISABLED)
            # Disable subhost connection when main host is disconnected
            self.subhost_connect_btn.config(state=tk.DISABLED)
            if self.subhost_connected:
                self.disconnect_subhost()
            
            # Stop auto-refresh
            self.auto_refresh = False
            self.auto_refresh_var.set(False)
            
            # Clear process list
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
    
    def set_subhost_connected_state(self, connected):
        """Update subhost UI based on connection state"""
        if connected:
            self.subhost_connect_btn.config(state=tk.DISABLED)
            self.subhost_disconnect_btn.config(state=tk.NORMAL)
            self.test_subhost_btn.config(state=tk.NORMAL)
        else:
            self.subhost_connect_btn.config(state=tk.NORMAL if self.pid_manager.connected else tk.DISABLED)
            self.subhost_disconnect_btn.config(state=tk.DISABLED)
            self.test_subhost_btn.config(state=tk.DISABLED)
