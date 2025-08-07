#!/usr/bin/env python3
"""
Build script to create an executable version of the Remote Server Log Manager GUI
Uses PyInstaller to package the application into a standalone executable
"""

import subprocess
import sys
import os
from pathlib import Path

def install_pyinstaller():
    """Install PyInstaller if not already installed"""
    try:
        import PyInstaller
        print("✅ PyInstaller is already installed")
        return True
    except ImportError:
        print("📦 Installing PyInstaller...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            print("✅ PyInstaller installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install PyInstaller: {e}")
            return False

def build_executable():
    """Build the executable using PyInstaller"""
    print("🔨 Building executable...")
    
    # Use full path to PyInstaller in QWAK2 environment
    pyinstaller_path = r"C:\Users\jaime\anaconda3\envs\QWAK2\Scripts\pyinstaller.exe"
    
    # PyInstaller command options
    cmd = [
        pyinstaller_path,
        "--onefile",                    # Create a single executable file
        "--windowed",                   # Hide console window (GUI app)
        "--name=RemoteServerLogManager", # Name of the executable
        "--icon=NONE",                  # No icon (can be added later)
        "--add-data=.env.example;.",    # Include example env file
        "--add-data=requirements.txt;.", # Include requirements
        "--clean",                      # Clean PyInstaller cache
        "--noconfirm",                  # Overwrite output without asking
        "remote_server_gui.py"          # Main script
    ]
    
    try:
        subprocess.check_call(cmd)
        print("✅ Executable built successfully!")
        
        # Check if executable was created
        exe_path = Path("dist/RemoteServerLogManager.exe")
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"📄 Executable created: {exe_path}")
            print(f"📊 Size: {size_mb:.1f} MB")
            return True
        else:
            print("❌ Executable file not found after build")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        return False
    except FileNotFoundError:
        print("❌ PyInstaller not found. Make sure it's installed and in PATH.")
        return False

def main():
    """Main build process"""
    print("🚀 Remote Server Log Manager - Executable Builder")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("remote_server_gui.py").exists():
        print("❌ remote_server_gui.py not found. Run this script from the project directory.")
        return False
    
    # Install PyInstaller if needed
    if not install_pyinstaller():
        return False
    
    # Build the executable
    if not build_executable():
        return False
    
    print("\n🎉 Build completed successfully!")
    print("\n📁 Output files:")
    print("   - dist/RemoteServerLogManager.exe  (Standalone executable)")
    print("   - build/ directory (Build artifacts - can be deleted)")
    print("   - RemoteServerLogManager.spec (Build specification)")
    
    print("\n💡 Usage:")
    print("   - Copy RemoteServerLogManager.exe to any computer")
    print("   - No Python installation required on target machine")
    print("   - Double-click to run the application")
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)
