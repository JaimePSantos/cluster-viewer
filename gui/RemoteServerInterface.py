#!/usr/bin/env python3
"""
Main GUI application for Remote Server Manager

Modular version with tabbed interface for logs and process management.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import threading
import queue
from pathlib import Path

# Import our custom modules
from core.config import Config
from core.ssh_manager import SSHManager
from core.log_analyzer import LogAnalyzer
from .file_selector import LogFileSelector
from .PIDTrackingInterface import PIDTrackingInterface


class RemoteServerInterface:
    """Main GUI application class with tabbed interface"""
    
    def __init__(self, root, title="Remote Server Manager"):
        """Initialize the GUI application"""
        self.root = root
        self.root.title(title)
        self.root.geometry("1000x700")  # Larger window for tabbed interface
        
        # Queue for thread communication
        self.message_queue = queue.Queue()
        
        # Initialize managers for log functionality
        self.ssh_manager = SSHManager(
            message_callback=self.log_message,
            status_callback=self.update_status
        )
        self.log_analyzer = LogAnalyzer(
            message_callback=self.log_message,
            status_callback=self.update_status,
            ssh_manager=self.ssh_manager
        )
        
        # Setup UI and start processing
        self.setup_ui()
        self.process_queue()
    
    def setup_ui(self):
        """Setup the user interface with tabs"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root, padding="10")
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.setup_log_manager_tab()
        self.setup_pid_tracker_tab()
        
        # Setup status bar
        self.setup_status_bar()
    
    def setup_log_manager_tab(self):
        """Setup the log manager tab"""
        # Create frame for log manager
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="📄 Log Manager")
        
        # Configure grid weights for log frame
        log_frame.columnconfigure(1, weight=1)
        log_frame.rowconfigure(4, weight=1)
        
        # Setup log manager sections
        self._setup_log_title(log_frame)
        self._setup_connection_settings(log_frame)
        self._setup_action_buttons(log_frame)
        self._setup_progress_bar(log_frame)
        self._setup_log_output_area(log_frame)
    
    def setup_pid_tracker_tab(self):
        """Setup the PID tracker tab"""
        # Create frame for PID tracker
        pid_frame = ttk.Frame(self.notebook)
        self.notebook.add(pid_frame, text="⚙️ Process Manager")
        
        # Initialize PID tracking interface
        self.pid_interface = PIDTrackingInterface(pid_frame, self.message_queue)
    
    def setup_status_bar(self):
        """Setup the status bar at the bottom"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 10))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT)
        
        # Progress bar (shared between tabs)
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.progress.pack(side=tk.RIGHT)
    
    def _setup_log_title(self, parent):
        """Setup the title section for log manager"""
        title_label = ttk.Label(parent, text="Remote Server Log Manager", 
                               font=Config.FONT_TITLE)
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
    
    def _setup_connection_settings(self, parent):
        """Setup the connection settings section"""
        conn_frame = ttk.LabelFrame(parent, text="Connection Settings", padding="10")
        conn_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        conn_frame.columnconfigure(1, weight=1)
        
        # Connection fields
        self._setup_connection_fields(conn_frame)
    
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
        
        # Remote and Local path row
        ttk.Label(parent, text="Remote Path:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.remote_path_var = tk.StringVar(value=Config.get_remote_path())
        self.remote_path_entry = ttk.Entry(parent, textvariable=self.remote_path_var)
        self.remote_path_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        ttk.Label(parent, text="Local Path:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        local_path_frame = ttk.Frame(parent)
        local_path_frame.grid(row=1, column=3, sticky=(tk.W, tk.E), pady=(5, 0))
        local_path_frame.columnconfigure(0, weight=1)
        
        self.local_path_var = tk.StringVar(value=Config.get_local_path())
        self.local_path_entry = ttk.Entry(local_path_frame, textvariable=self.local_path_var)
        self.local_path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        browse_btn = ttk.Button(local_path_frame, text="Browse", command=self.browse_local_path)
        browse_btn.grid(row=0, column=1)
    
    def _setup_action_buttons(self, parent):
        """Setup the action buttons section"""
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        # Main action buttons
        self.download_btn = ttk.Button(button_frame, text="Download Logs", 
                                      command=self.download_logs, style="Accent.TButton")
        self.download_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.analyze_btn = ttk.Button(button_frame, text="Analyze Logs", 
                                     command=self.analyze_logs)
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear output button
        self.clear_btn = ttk.Button(button_frame, text="Clear Log Output", 
                                   command=self.clear_output)
        self.clear_btn.pack(side=tk.LEFT)
    
    def _setup_progress_bar(self, parent):
        """Setup progress bar for log manager"""
        # Note: Progress bar is now in the status bar at the bottom
        pass
    
    def _setup_log_output_area(self, parent):
        """Setup the output text area for log manager"""
        output_frame = ttk.LabelFrame(parent, text="Log Output", padding="5")
        output_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Clear button
        clear_btn = ttk.Button(output_frame, text="Clear Output", command=self.clear_output)
        clear_btn.grid(row=1, column=0, sticky=tk.E, pady=(5, 0))
    
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
                elif msg_type == "ssh_connected":
                    # Handle SSH connection for PID tracker
                    if hasattr(self, 'pid_interface'):
                        self.pid_interface.set_connected_state(True)
                elif msg_type == "ssh_disconnected":
                    # Handle SSH disconnection for PID tracker
                    if hasattr(self, 'pid_interface'):
                        self.pid_interface.set_connected_state(False)
                elif msg_type == "update_process_list":
                    # Update process list in PID tracker
                    if hasattr(self, 'pid_interface'):
                        self.pid_interface.update_process_list(message)
                elif msg_type == "subhost_connected":
                    # Handle subhost connection for PID tracker
                    if hasattr(self, 'pid_interface'):
                        self.pid_interface.set_subhost_connected_state(True)
                elif msg_type == "subhost_disconnected":
                    # Handle subhost disconnection for PID tracker
                    if hasattr(self, 'pid_interface'):
                        self.pid_interface.set_subhost_connected_state(False)
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(Config.QUEUE_CHECK_INTERVAL, self.process_queue)
    
    def clear_output(self):
        """Clear the log output text area"""
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
            
            # Get password
            password = Config.get_password()
            if not password:
                # Use a simple dialog for password input
                password = simpledialog.askstring("Password", 
                                                f"Enter password for {username}@{hostname}:", 
                                                show='*')
                if not password:
                    self.log_message("Password input cancelled.")
                    return
            
            # Connect and download
            if self.ssh_manager.connect(hostname, username, password):
                self.ssh_manager.download_files(remote_path, local_path)
                self.log_message("Download completed successfully!")
                self.update_status("Download completed")
            else:
                self.update_status("Connection failed")
            
        except Exception as e:
            self.log_message(f"❌ Error: {str(e)}")
            self.update_status("Error occurred")
        finally:
            self.ssh_manager.close()
            self.set_progress(False)
            self.message_queue.put(("enable_buttons", None))
    
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
            log_files = self.log_analyzer.find_log_files(local_path)
            
            if not log_files:
                self.log_message("❌ No log files found to analyze")
                self.log_message(f"Searched in: {local_path}")
                return
            
            self.log_message(f"Found {len(log_files)} log file(s)")
            
            # Show log file selection dialog
            file_selector = LogFileSelector(self.root, log_files, local_path)
            selected_files = file_selector.show_dialog()
            
            if not selected_files:
                self.log_message("No log files selected for analysis")
                return
            
            # Analyze selected files
            for log_file in selected_files:
                self.log_message(f"\n{'='*60}")
                self.log_message(f"Analyzing {Path(log_file).name}")
                self.log_message('='*60)
                self.log_analyzer.analyze_single_log(log_file)
            
            self.log_message("\n✅ Log analysis completed!")
            self.update_status("Analysis completed")
            
        except Exception as e:
            self.log_message(f"❌ Error during analysis: {str(e)}")
            self.update_status("Analysis error")
        finally:
            self.set_progress(False)
            self.message_queue.put(("enable_buttons", None))


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
    
    # Configure custom styles
    style.configure('Accent.TButton', foreground='white')
    
    # Create and run the application
    app = RemoteServerInterface(root, "Remote Server Manager")
    
    # Handle window closing
    def on_closing():
        # Close any active connections
        if hasattr(app, 'ssh_manager'):
            app.ssh_manager.close()
        if hasattr(app, 'pid_interface') and hasattr(app.pid_interface, 'pid_manager'):
            app.pid_interface.pid_manager.close()
        
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
