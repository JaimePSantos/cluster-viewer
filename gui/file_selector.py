#!/usr/bin/env python3
"""
File selection dialog for Remote Server Log Manager

Provides a sophisticated file selection interface with folder organization.
"""

import tkinter as tk
from tkinter import ttk
import os
from datetime import datetime


class LogFileSelector:
    """Handles log file selection with folder organization"""
    
    def __init__(self, parent, log_files, local_path):
        """Initialize the file selector dialog"""
        self.parent = parent
        self.log_files = log_files
        self.local_path = local_path
        self.selected_files = []
        self.current_log_files = log_files.copy()
        self.item_to_file = {}
        self.folder_items = {}
        self.folder_files = {}  # Cache for folder contents
        self.folder_loaded = {}  # Track which folders have been loaded
        self.dialog = None
        self.tree = None
    
    def show_dialog(self):
        """Show the file selection dialog and return selected files"""
        self._create_dialog()
        self._setup_ui()
        self._populate_tree()
        
        # Wait for dialog to close
        self.dialog.wait_window()
        
        return self.selected_files
    
    def _create_dialog(self):
        """Create the main dialog window"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Select Log Files to Analyze")
        self.dialog.geometry("800x600")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (
            self.parent.winfo_rootx() + 50, 
            self.parent.winfo_rooty() + 50
        ))
    
    def _setup_ui(self):
        """Setup the user interface elements"""
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Instructions and sort controls
        self._setup_header(main_frame)
        
        # TreeView with scrollbar for hierarchical display
        self._setup_tree(main_frame)
        
        # Buttons
        self._setup_buttons(main_frame)
        
        # Info labels
        self._setup_info_labels(main_frame)
    
    def _setup_header(self, parent):
        """Setup header with instructions and controls"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Select log files to analyze (organized by folder):", 
                 font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        # Sort button
        sort_btn = ttk.Button(header_frame, text="Sort by Recently Modified", 
                             command=self._sort_by_modified)
        sort_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Expand/Collapse buttons
        expand_btn = ttk.Button(header_frame, text="Expand All", 
                               command=self._expand_all_folders)
        expand_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        collapse_btn = ttk.Button(header_frame, text="Collapse All", 
                                 command=self._collapse_all_folders)
        collapse_btn.pack(side=tk.RIGHT)
    
    def _setup_tree(self, parent):
        """Setup the TreeView for file selection"""
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create TreeView with columns
        columns = ('size', 'modified')
        self.tree = ttk.Treeview(tree_frame, columns=columns, selectmode='extended')
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure columns
        self.tree.heading('#0', text='File/Folder', anchor=tk.W)
        self.tree.heading('size', text='Size', anchor=tk.E)
        self.tree.heading('modified', text='Modified', anchor=tk.CENTER)
        
        self.tree.column('#0', width=400, minwidth=200)
        self.tree.column('size', width=80, minwidth=60)
        self.tree.column('modified', width=140, minwidth=120)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        
        h_scrollbar = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        h_scrollbar.pack(fill=tk.X)
        self.tree.configure(xscrollcommand=h_scrollbar.set)
        
        # Bind folder expansion events
        self.tree.bind('<<TreeviewOpen>>', self._on_folder_expand)
    
    def _setup_buttons(self, parent):
        """Setup action buttons"""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X)
        
        # Left side buttons
        ttk.Button(button_frame, text="Select All Files", 
                  command=self._select_all_files).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Clear Selection", 
                  command=self._clear_selection).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Analyze Selected", 
                  command=self._analyze_selected).pack(side=tk.LEFT, padx=(0, 10))
        
        # Right side buttons
        ttk.Button(button_frame, text="Cancel", 
                  command=self._cancel).pack(side=tk.RIGHT)
    
    def _setup_info_labels(self, parent):
        """Setup informational labels"""
        total_folders = len(set(os.path.dirname(os.path.relpath(f, self.local_path)) 
                               if os.path.dirname(os.path.relpath(f, self.local_path)) 
                               else "." for f in self.current_log_files))
        
        info_text = (f"Found {len(self.current_log_files)} log files in "
                    f"{total_folders} folders. Expand folders to view files, "
                    f"then select and click 'Analyze Selected'.")
        info_label = ttk.Label(parent, text=info_text, 
                              font=("Arial", 9), foreground="gray")
        info_label.pack(pady=(5, 0))
        
        instructions_text = ("💡 Tip: Click folder ▶ to expand and load files, "
                           "or use 'Expand All' to load all folders at once")
        instructions_label = ttk.Label(parent, text=instructions_text, 
                                     font=("Arial", 8), foreground="blue")
        instructions_label.pack(pady=(2, 0))
    
    def _populate_tree(self):
        """Populate the tree with folders first (collapsed), files loaded on demand"""
        # Clear existing items
        self.tree.delete(*self.tree.get_children())
        self.item_to_file.clear()
        self.folder_items.clear()
        self.folder_files.clear()
        self.folder_loaded.clear()
        
        # Group files by directory (but don't process file details yet)
        for log_file in self.current_log_files:
            rel_path = os.path.relpath(log_file, self.local_path)
            folder = os.path.dirname(rel_path) if os.path.dirname(rel_path) else "."
            
            if folder not in self.folder_files:
                self.folder_files[folder] = []
            self.folder_files[folder].append(log_file)
        
        # Sort folders and create folder items (collapsed by default)
        sorted_folders = sorted(self.folder_files.keys())
        
        for folder in sorted_folders:
            # Create folder item
            folder_display = folder if folder != "." else "📁 Root Directory"
            if folder != ".":
                folder_display = f"📁 {folder}"
            
            file_count = len(self.folder_files[folder])
            folder_display += f" ({file_count} files)"
            
            # Create folder item - COLLAPSED by default (open=False)
            folder_item = self.tree.insert('', 'end', text=folder_display, 
                                         open=False, values=("", ""))
            self.folder_items[folder] = folder_item
            self.folder_loaded[folder] = False
            
            # Add a dummy child to show the expand triangle
            # This will be replaced with actual files when expanded
            self.tree.insert(folder_item, 'end', text="Loading...", values=("", ""))
    
    def _on_folder_expand(self, event):
        """Handle folder expansion - load files on demand"""
        # Get the item that was just expanded
        expanded_item = self.tree.focus()
        if not expanded_item:
            return
        
        # Find which folder was expanded
        folder_path = None
        for folder, item in self.folder_items.items():
            if item == expanded_item:
                folder_path = folder
                break
        
        if folder_path and not self.folder_loaded[folder_path]:
            self._load_folder_contents(folder_path, expanded_item)
    
    def _load_folder_contents(self, folder_path, folder_item):
        """Load the actual file contents for a folder"""
        # Remove dummy "Loading..." item
        children = self.tree.get_children(folder_item)
        for child in children:
            self.tree.delete(child)
        
        # Get global file counter for numbering
        file_counter = 1
        for folder in sorted(self.folder_files.keys()):
            if folder == folder_path:
                break
            file_counter += len(self.folder_files[folder])
        
        # Add files in this folder
        folder_file_list = self.folder_files[folder_path]
        
        for log_file in folder_file_list:
            rel_path = os.path.relpath(log_file, self.local_path)
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
            file_item = self.tree.insert(folder_item, 'end', text=file_display, 
                                      values=(size_str, time_str))
            
            # Map tree item to actual file path
            self.item_to_file[file_item] = log_file
            file_counter += 1
        
        # Mark folder as loaded
        self.folder_loaded[folder_path] = True
    
    def _sort_by_modified(self):
        """Sort files by modification time (most recent first)"""
        try:
            self.current_log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            # Reset folder loading state and repopulate
            self.folder_loaded.clear()
            self._populate_tree()
        except Exception as e:
            print(f"Error sorting files: {str(e)}")
    
    def _expand_all_folders(self):
        """Expand all folder items and load their contents"""
        for folder_path, item in self.folder_items.items():
            self.tree.item(item, open=True)
            if not self.folder_loaded[folder_path]:
                self._load_folder_contents(folder_path, item)
    
    def _collapse_all_folders(self):
        """Collapse all folder items"""
        for item in self.folder_items.values():
            self.tree.item(item, open=False)
    
    def _select_all_files(self):
        """Select all file items (not folders)"""
        for item in self.item_to_file.keys():
            self.tree.selection_add(item)
    
    def _clear_selection(self):
        """Clear all selections"""
        self.tree.selection_remove(self.tree.selection())
    
    def _analyze_selected(self):
        """Analyze selected files and close dialog"""
        selection = self.tree.selection()
        if selection:
            # Only include actual files (not folders)
            for item in selection:
                if item in self.item_to_file:
                    self.selected_files.append(self.item_to_file[item])
        self.dialog.destroy()
    
    def _cancel(self):
        """Cancel and close dialog"""
        self.dialog.destroy()
