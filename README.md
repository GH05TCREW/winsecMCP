# Windows Security MCP (winsecMCP)

An AI-powered agent for automating Windows security hardening tasks.

## Overview

winsecMCP is a Python-based security tool that helps administrators automate Windows security configuration. It provides a set of tools to check and modify security settings including:

- Firewall configuration
- Remote Desktop Protocol (RDP) settings
- User Account Control (UAC) settings
- Account policies (password requirements, lockout policies)
- Service management and hardening
- User account management

## Requirements

- Windows operating system
- Python 3.6+
- Administrator privileges (for most operations)
- Required Python packages:
  - mcp (MCP for the agent interface)
  - asyncio

## Usage

Run the script with administrator privileges:

```powershell
python winsecMCP.py
```

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