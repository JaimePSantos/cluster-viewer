#!/usr/bin/env python3
"""
Remote Server Manager - Main Entry Point

Simple entry point to launch the Remote Server Manager GUI application.
"""

from gui.RemoteServerInterface import main as gui_main


def main():
    """Main function to launch the Remote Server Manager application"""
    # Use the main function from RemoteServerInterface
    gui_main()


if __name__ == "__main__":
    main()
