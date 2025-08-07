# Remote Server Log Manager

A Python GUI application for downloading and analyzing log files from remote servers via SFTP/SSH. Features an intuitive interface for monitoring remote processes through heartbeat log analysis and automatic timezone detection.

## Features
- 🔗 **SFTP/SSH Connection** - Secure remote server access with automatic host key management
- 📥 **Recursive Download** - Download entire log directory structures with progress tracking  
- 📊 **Heartbeat Analysis** - Automatically detect process status, gaps, and timeline analysis
- 🗂️ **Folder Organization** - TreeView interface with expandable folders and file sorting
- 🌍 **Timezone Management** - Automatic server timezone detection with manual override
- ⚙️ **Environment Config** - Load connection settings from `.env` files

## Quick Start
1. **Install dependencies**: `pip install -r requirements.txt`
2. **Run application**: `python remote_server_gui.py`
3. **Configure connection** in the GUI (hostname, username, paths)
4. **Download logs** and **analyze** with the folder-based file selection

## Dependencies
- `paramiko` - SSH/SFTP client
- `python-dotenv` - Environment variables
- `tkinter` - GUI framework (included with Python)
