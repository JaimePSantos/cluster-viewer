#!/usr/bin/env python3
"""
Test script for PID Manager functionality

This script tests the PID manager without requiring a GUI.
"""

from core.pid_manager import PIDManager
import time


def test_pid_manager():
    """Test the PID manager functionality"""
    print("🧪 Testing PID Manager functionality...")
    
    # Create PID manager instance
    pid_manager = PIDManager()
    
    print("✅ PID Manager created successfully!")
    print("📋 Available methods:")
    methods = [method for method in dir(pid_manager) if not method.startswith('_')]
    for method in methods:
        print(f"   - {method}")
    
    print("\n🔧 Testing basic functionality...")
    
    # Test connection status
    print(f"Connected: {pid_manager.connected}")
    
    # Test log message
    pid_manager.log_message("Test log message")
    
    # Test status update
    pid_manager.update_status("Testing status")
    
    print("✅ Basic functionality test completed!")
    
    # Note: We don't test actual SSH connection here as it requires credentials
    print("\n📝 Note: To test SSH functionality, use the GUI interface")
    print("   1. Launch the application: C:\\Users\\jaime\\anaconda3\\envs\\QWAK2\\python.exe gui-main.py")
    print("   2. Go to the 'Process Manager' tab")
    print("   3. Enter your SSH credentials and connect")
    print("   4. Use the process management features")


if __name__ == "__main__":
    test_pid_manager()
