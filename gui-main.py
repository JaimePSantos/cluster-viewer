#!/usr/bin/env python3
"""
Remote Server Log Manager - Main Entry Point

Simple entry point to launch the Remote Server Log Manager GUI application.
"""

import tkinter as tk
from tkinter import ttk

from gui.RemoteServerInterface import RemoteServerInterface


def main():
    """Main function to launch the Remote Server Log Manager application"""
    # Create the main window
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
    app = RemoteServerInterface(root, title="Remote Server Log Manager")
    
    # Set window constraints
    root.minsize(800, 600)
    root.maxsize(1400, 1000)
    
    # Handle window closing gracefully
    def on_closing():
        try:
            root.quit()
            root.destroy()
        except Exception:
            pass  # Ignore errors during shutdown
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Start the application
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")


if __name__ == "__main__":
    main()
