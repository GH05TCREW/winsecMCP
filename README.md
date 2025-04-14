## Overview

winsecMCP is a Python-based MCP server with Claude for client that helps administrators automate Windows security configuration. It provides a set of tools to check and modify security settings including:

- Firewall configuration
- Remote Desktop Protocol (RDP) settings
- User Account Control (UAC) settings
- Account policies (password requirements, lockout policies)
- Service management and hardening
- User account management

## Requirements

- Windows OS
- Python 3.10+
- Administrator privileges (for most operations)
- Required Python packages:
  - mcp

## Usage

Run the script with administrator privileges and start Claude client:

```powershell
python winsecMCP.py
```

Make sure to add this to your `claude_desktop_config.json` file:

```json
{
  "mcpServers": {
    "windows_hardening_agent": {
      "command": "python",
      "args": [
        "C:\\Path\\to\\hardening_server.py"
      ]
    }
  }
}

## Features

### Information Gathering
- Get system status and privilege level
- Check RDP, firewall, UAC, and guest account status
- Review password policies and account lockout settings
- Scan for potentially insecure services

### Security Hardening
- Enable/disable RDP
- Configure Windows Firewall
- Manage UAC settings
- Set password and account lockout policies
- Disable unnecessary services
- Manage user accounts and group memberships

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Disclaimer

This tool modifies system settings that can impact system functionality. Always test in a controlled environment before using in production. The authors are not responsible for any damages or issues resulting from the use of this tool. 
