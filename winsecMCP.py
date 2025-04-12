# filename: winsecMCP.py
# --- Imports ---
import asyncio
import subprocess
import re
import logging
from typing import Any, Dict, List, Tuple # More specific type hints

# --- MCP Imports ---
from mcp.server.fastmcp import FastMCP

# --- Initialize Logging ---
# Logs output to the console where the server is run.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HardeningServer")

# --- Initialize FastMCP Server ---
# Give it a descriptive name and description for Claude.
mcp = FastMCP(
    name="windows_hardening_agent",
    description="Provides tools and resources to check and configure Windows security settings based on hardening scripts. Requires Administrator privileges to run."
)

# --- Helper Function to Run Commands ---
def run_command(cmd_list: List[str], check: bool = False, timeout: int = 20) -> Dict[str, Any]:
    """
    Runs a Windows command using subprocess, captures output, and handles common errors.

    Args:
        cmd_list: The command and its arguments as a list of strings.
        check: If True, raise CalledProcessError on non-zero exit code (use False to handle errors manually).
        timeout: Timeout in seconds for the command.

    Returns:
        A dictionary containing:
        {
            "stdout": str,
            "stderr": str,
            "returncode": int
        }
    """
    command_str = ' '.join(cmd_list)
    logger.info(f"Executing command: {command_str}")
    try:
        # Using shell=True can be necessary for built-in commands like 'reg', 'netsh', 'net' on Windows.
        # Ensure input is controlled and not user-generated if using shell=True with dynamic parts.
        # Use UTF-8 encoding, ignore errors for robustness against weird console output.
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            shell=True,
            timeout=timeout,
            check=check,
            encoding='utf-8',
            errors='ignore'
        )
        logger.info(f"Command finished: {command_str} (Return Code: {result.returncode})")
        if result.stderr:
            # Log stderr as warning, it might contain non-error messages too
            logger.warning(f"Command stderr for '{command_str}': {result.stderr.strip()}")
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return code {e.returncode}: {command_str}", exc_info=False) # Log error without full stack trace unless debugging
        logger.error(f"Stderr: {e.stderr.strip()}")
        return {
             "stdout": e.stdout.strip() if e.stdout else "",
             "stderr": e.stderr.strip() if e.stderr else f"Error: CalledProcessError code {e.returncode}",
             "returncode": e.returncode
        }
    except subprocess.TimeoutExpired:
         logger.error(f"Command timed out after {timeout}s: {command_str}")
         return {
             "stdout": "",
             "stderr": f"Error: Command timed out after {timeout}s",
             "returncode": -1 # Custom code for timeout
         }
    except Exception as e:
        logger.error(f"An unexpected error occurred running command: {command_str}", exc_info=True) # Log full trace for unexpected
        return {
            "stdout": "",
            "stderr": f"Error: Unexpected Exception - {e}",
            "returncode": -2 # Custom code for other errors
        }

# --- Check Admin Privileges Helper ---
def check_admin_privileges() -> bool:
    """Check if the current process has Administrator privileges."""
    try:
        check_cmd = ['net', 'session']
        result = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Error checking admin privileges: {e}")
        return False

# --- MCP Tools (Checks/Read-only State) ---

@mcp.tool()
def get_system_status() -> Dict[str, Any]:
    """
    Returns the overall system status, including admin privileges.
    
    Returns:
        dict: Status: {"is_admin": bool, "server_info": str}
    """
    logger.info("Checking system status...")
    
    # Direct check for admin status
    is_admin = check_admin_privileges()
    
    status = {
        "is_admin": is_admin,
        "server_info": f"Windows Hardening MCP Server - Running {'with' if is_admin else 'WITHOUT'} Administrator privileges"
    }
    
    logger.info(f"System Status Check Result: {status}")
    return status

@mcp.tool()
def get_rdp_status() -> Dict[str, Any]:
    """
    Checks the status of Remote Desktop Protocol (RDP) connections via registry
    (fDenyTSConnections) and the associated firewall rule state (Remote Desktop group).

    Returns:
        dict: Status: {"rdp_connections_allowed": bool, "firewall_rule_enabled": bool, "details": str}
    """
    logger.info("Checking RDP status...")
    # Check registry key HKLM\...\Terminal Server fDenyTSConnections
    # Value 0 means RDP is allowed (Deny=False), 1 means disallowed (Deny=True)
    reg_cmd = ['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server', '/v', 'fDenyTSConnections']
    reg_result = run_command(reg_cmd)

    rdp_allowed_registry = False
    if reg_result["returncode"] == 0:
        # Extract the actual value from the registry output
        value_match = re.search(r"fDenyTSConnections\s+REG_DWORD\s+(0x\d+)", reg_result["stdout"], re.IGNORECASE)
        if value_match:
            # Check if the value is explicitly 0x0 (RDP allowed)
            rdp_allowed_registry = value_match.group(1).lower() == "0x0"

    # Check firewall rule status for the 'Remote Desktop' group
    fw_cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'group="remote desktop"', 'status=enabled']
    fw_result = run_command(fw_cmd)
    firewall_rules_enabled = False
    # If the command finds enabled rules, output isn't empty and usually doesn't start with "No rules match"
    if fw_result["returncode"] == 0 and fw_result["stdout"] and not fw_result["stdout"].strip().startswith("No rules match"):
         firewall_rules_enabled = True

    status = {
        "rdp_connections_allowed": rdp_allowed_registry,
        "firewall_rules_enabled": firewall_rules_enabled, # Note: Checks if *any* rule in the group is enabled
        "details": f"Registry check return code: {reg_result['returncode']}. Firewall check return code: {fw_result['returncode']}."
    }
    logger.info(f"RDP Status Check Result: {status}")
    return status

@mcp.tool()
def get_firewall_status() -> Dict[str, Any]:
    """
    Checks if the Windows Firewall is enabled for the Domain, Private, and Public profiles.

    Returns:
        dict: Status: {"domain_profile_enabled": bool, "private_profile_enabled": bool, "public_profile_enabled": bool, "details": str}
    """
    logger.info("Checking Firewall status...")
    command = ['netsh', 'advfirewall', 'show', 'allprofiles']
    result = run_command(command)

    # Default to False
    status = {
        "domain_profile_enabled": False,
        "private_profile_enabled": False,
        "public_profile_enabled": False,
        "details": f"Command return code: {result['returncode']}. Output head: {result['stdout'][:150]}..."
    }

    if result["returncode"] == 0:
        # Extract the state value properly instead of just looking for "ON"
        domain_match = re.search(r"Domain Profile Settings:.*?\n.*?State\s+(\w+)", result["stdout"], re.IGNORECASE | re.DOTALL)
        private_match = re.search(r"Private Profile Settings:.*?\n.*?State\s+(\w+)", result["stdout"], re.IGNORECASE | re.DOTALL)
        public_match = re.search(r"Public Profile Settings:.*?\n.*?State\s+(\w+)", result["stdout"], re.IGNORECASE | re.DOTALL)
        
        # Only set to True if the state is explicitly "ON"
        status["domain_profile_enabled"] = bool(domain_match and domain_match.group(1).upper() == "ON")
        status["private_profile_enabled"] = bool(private_match and private_match.group(1).upper() == "ON")
        status["public_profile_enabled"] = bool(public_match and public_match.group(1).upper() == "ON")

    logger.info(f"Firewall Status Check Result: {status}")
    return status

@mcp.tool()
def get_uac_status() -> Dict[str, Any]:
    """
    Checks the status of User Account Control (UAC) via multiple registry keys.
    Considers both EnableLUA and ConsentPromptBehaviorAdmin settings.

    Returns:
        dict: Status: {"uac_enabled": bool, "notification_level": str, "details": str}
    """
    logger.info("Checking UAC status...")
    # Check primary UAC switch - EnableLUA
    reg_cmd = ['reg', 'query', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', '/v', 'EnableLUA']
    reg_result = run_command(reg_cmd)

    # Also check notification level - ConsentPromptBehaviorAdmin
    behavior_cmd = ['reg', 'query', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', '/v', 'ConsentPromptBehaviorAdmin']
    behavior_result = run_command(behavior_cmd)

    uac_enabled = False
    notification_level = "Unknown"
    
    # Check if UAC is enabled at all (EnableLUA)
    if reg_result["returncode"] == 0:
        value_match = re.search(r"EnableLUA\s+REG_DWORD\s+(0x\d+)", reg_result["stdout"], re.IGNORECASE)
        if value_match:
            # UAC is enabled if EnableLUA = 0x1
            uac_enabled = value_match.group(1).lower() == "0x1"
    
    # Check notification level if UAC is enabled
    if uac_enabled and behavior_result["returncode"] == 0:
        level_match = re.search(r"ConsentPromptBehaviorAdmin\s+REG_DWORD\s+(0x\d+)", behavior_result["stdout"], re.IGNORECASE)
        if level_match:
            level_value = level_match.group(1).lower()
            if level_value == "0x0":
                notification_level = "Never notify"
            elif level_value == "0x1":
                notification_level = "Notify only when apps try to make changes (no dimming)"
            elif level_value == "0x2":
                notification_level = "Always notify (with secure desktop)" 
            elif level_value == "0x5":
                notification_level = "Notify only when apps try to make changes (with dimming)"
            else:
                notification_level = f"Unknown level ({level_value})"

    status = {
        "uac_enabled": uac_enabled,
        "notification_level": notification_level,
        "details": f"Registry check return code: {reg_result['returncode']}."
    }
    logger.info(f"UAC Status Check Result: {status}")
    return status

@mcp.tool()
def get_guest_account_status() -> Dict[str, Any]:
    """
    Checks if the local Guest account is active.

    Returns:
        dict: Status: {"guest_account_active": bool, "details": str}
    """
    logger.info("Checking Guest account status...")
    # Use 'net user Guest' and parse the output
    cmd = ['net', 'user', 'Guest']
    result = run_command(cmd)

    guest_active = False
    # Check if command succeeded and "Account active" line says "Yes"
    if result["returncode"] == 0 and re.search(r"Account active\s+Yes", result["stdout"], re.IGNORECASE):
        guest_active = True
        # Handle case where account might not exist (less common for Guest)
    elif result["returncode"] != 0 and "The user name could not be found" in result["stderr"]:
         logger.warning("Guest account not found.")
         # Treat as inactive if not found

    status = {
        "guest_account_active": guest_active,
        "details": f"Command return code: {result['returncode']}."
    }
    logger.info(f"Guest Account Status Check Result: {status}")
    return status


# --- MCP Tools (Actions/Security Summary) ---

@mcp.tool()
def get_security_summary() -> Dict[str, Any]:
    """
    Generates a comprehensive security summary by evaluating multiple security settings
    without making any changes to the system. Provides a score and recommendations.
    
    Returns:
        dict: Comprehensive security status including system checks and recommendations
    """
    logger.info("Generating comprehensive security summary...")
    
    try:
        # Collect all status information from tools
        system_status = get_system_status()
        rdp_status = get_rdp_status()
        firewall_status = get_firewall_status()
        uac_status = get_uac_status()
        guest_status = get_guest_account_status()
        
        # Additional checks
        password_policy = check_password_policy()
        account_lockout = check_account_lockout()
        insecure_services = check_insecure_services()
        network_security = check_network_security()
        
        # Evaluate overall security score (enhanced implementation)
        security_score = 0
        max_score = 15  # Increased from 5 to 15 with additional checks
        secure_items = []
        vulnerable_items = []
        recommendations = []
        
        # Check if admin privileges (required for hardening)
        if system_status.get("is_admin", False):
            secure_items.append("Running with administrator privileges")
        else:
            vulnerable_items.append("NOT running with administrator privileges - limited functionality")
            recommendations.append("Run this tool with Administrator privileges to enable all hardening features")
        
        # Check RDP status (more secure when disabled)
        if not rdp_status.get("rdp_connections_allowed", True):
            secure_items.append("RDP connections disabled")
            security_score += 1
        else:
            vulnerable_items.append("RDP connections enabled")
            recommendations.append("Disable RDP if not required, or ensure Network Level Authentication is enabled")
        
        # Check firewall status (all profiles should be enabled)
        if (firewall_status.get("domain_profile_enabled", False) and 
            firewall_status.get("private_profile_enabled", False) and 
            firewall_status.get("public_profile_enabled", False)):
            secure_items.append("Firewall enabled on all profiles")
            security_score += 1
        else:
            vulnerable_items.append("Firewall disabled on one or more profiles")
            recommendations.append("Enable Windows Firewall for all network profiles (Domain, Private, Public)")
        
        # Check UAC status - improved to consider notification level
        uac_is_enabled = uac_status.get("uac_enabled", False)
        uac_level = uac_status.get("notification_level", "Unknown")
        
        if uac_is_enabled and uac_level != "Never notify":
            secure_items.append(f"User Account Control (UAC) enabled with notification level: {uac_level}")
            security_score += 1
        else:
            if not uac_is_enabled:
                vulnerable_items.append("User Account Control (UAC) is completely disabled")
            elif uac_level == "Never notify":
                vulnerable_items.append("User Account Control (UAC) is set to 'Never notify' (not recommended)")
            else:
                vulnerable_items.append("User Account Control (UAC) has an unknown configuration")
            
            recommendations.append("Enable User Account Control (UAC) with at least 'Notify only when apps try to make changes' level")
        
        # Check Guest account
        if not guest_status.get("guest_account_active", True):
            secure_items.append("Guest account disabled")
            security_score += 1
        else:
            vulnerable_items.append("Guest account active")
            recommendations.append("Disable the Guest account to prevent unauthorized access")
        
        # Check password policy (length, complexity, history, age)
        if password_policy.get("min_length", 0) >= 10:
            secure_items.append(f"Password minimum length is {password_policy.get('min_length')} characters (good)")
            security_score += 1
        else:
            vulnerable_items.append(f"Password minimum length is only {password_policy.get('min_length')} characters")
            recommendations.append("Set minimum password length to at least 10 characters")
        
        if password_policy.get("complexity_enabled", False):
            secure_items.append("Password complexity requirements are enabled")
            security_score += 1
        else:
            vulnerable_items.append("Password complexity requirements are disabled")
            recommendations.append("Enable password complexity requirements")
        
        if password_policy.get("history_count", 0) >= 24:
            secure_items.append(f"Password history count is {password_policy.get('history_count')} (good)")
            security_score += 1
        else:
            vulnerable_items.append(f"Password history count is only {password_policy.get('history_count')}")
            recommendations.append("Set password history to remember at least 24 previous passwords")
        
        # Check account lockout policy
        if account_lockout.get("threshold", 0) > 0 and account_lockout.get("threshold", 0) <= 10:
            secure_items.append(f"Account lockout threshold is {account_lockout.get('threshold')} attempts (good)")
            security_score += 1
        else:
            vulnerable_items.append(f"Account lockout threshold is {'disabled' if account_lockout.get('threshold', 0) == 0 else 'too high'}")
            recommendations.append("Set account lockout threshold to 10 or fewer invalid attempts")
        
        if account_lockout.get("duration", 0) >= 30:
            secure_items.append(f"Account lockout duration is {account_lockout.get('duration')} minutes (good)")
            security_score += 1
        else:
            vulnerable_items.append(f"Account lockout duration is only {account_lockout.get('duration')} minutes")
            recommendations.append("Set account lockout duration to at least 30 minutes")
        
        # Check for insecure services
        for service, status in insecure_services.items():
            if status.get("running", False):
                vulnerable_items.append(f"Insecure service '{service}' is running")
                recommendations.append(f"Disable the {service} service")
            else:
                secure_items.append(f"Insecure service '{service}' is not running")
                security_score += 0.25  # Partial credit for each secure service
        
        # Network security checks (SMB, NTLM, LLMNR, etc.)
        for feature, status in network_security.items():
            if status.get("secure", False):
                secure_items.append(f"Network security: {feature} is secure")
                security_score += 0.25  # Partial credit for each secure feature
            else:
                vulnerable_items.append(f"Network security: {feature} is insecure")
                recommendations.append(f"Secure {feature} by {status.get('recommendation', '')}")
        
        # Round the final score to handle partial points
        security_score = round(security_score, 1)
        
        # Create summary
        summary = {
            "security_score": security_score,
            "security_score_max": max_score,
            "security_percentage": round((security_score / max_score) * 100, 1),
            "secure_items": secure_items,
            "vulnerable_items": vulnerable_items,
            "recommendations": recommendations,
            "admin_access": system_status.get("is_admin", False),
            "details": {
                "rdp": rdp_status,
                "firewall": firewall_status,
                "uac": uac_status,
                "guest_account": guest_status,
                "system": system_status,
                "password_policy": password_policy,
                "account_lockout": account_lockout,
                "insecure_services": insecure_services,
                "network_security": network_security
            }
        }
        
        logger.info(f"Security summary generated. Score: {security_score}/{max_score}")
        return summary
        
    except Exception as e:
        logger.error(f"Error generating security summary: {e}", exc_info=True)
        return {
            "status": "failure",
            "message": f"Failed to generate security summary: {str(e)}",
            "error": str(e)
        }

@mcp.tool()
def disable_rdp() -> Dict[str, str]:
    """
    Disables Remote Desktop Protocol (RDP) connections by setting registry key
    fDenyTSConnections=1 and disabling the 'Remote Desktop' firewall rule group.

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info("Attempting to disable RDP...")
    reg_cmd = ['reg', 'add', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server', '/v', 'fDenyTSConnections', '/t', 'REG_DWORD', '/d', '1', '/f']
    fw_cmd = ['netsh', 'advfirewall', 'firewall', 'set', 'rule', 'group="remote desktop"', 'new', 'enable=no']

    reg_result = run_command(reg_cmd)
    fw_result = run_command(fw_cmd) # Attempt even if reg failed

    success = reg_result["returncode"] == 0 # Base success on registry change
    message = f"Registry (fDenyTSConnections=1): {'Succeeded' if success else 'Failed (' + str(reg_result['returncode']) + ')'}. "
    message += f"Firewall (Disable Rule Group 'remote desktop'): {'Succeeded' if fw_result['returncode'] == 0 else 'Failed/Not Applicable (' + str(fw_result['returncode']) + ')'}."

    if not success:
         message += f" Registry Error: {reg_result['stderr']}"
    if fw_result["returncode"] != 0:
         message += f" Firewall Error: {fw_result['stderr']}"

    status = "success" if success else "failure"
    logger.info(f"Disable RDP Result: {status} - {message}")
    return {"status": status, "message": message}


@mcp.tool()
def enable_rdp() -> Dict[str, str]:
    """
    Enables RDP connections (sets fDenyTSConnections=0), enables the firewall rule group,
    and requires Network Level Authentication (NLA) by setting UserAuthentication=1.

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info("Attempting to enable RDP (with NLA)...")
    # Command parts - use raw strings (r"...") for paths with backslashes
    reg_allow_cmd = ['reg', 'add', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server', '/v', 'fDenyTSConnections', '/t', 'REG_DWORD', '/d', '0', '/f']
    reg_nla_cmd = ['reg', 'add', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', '/v', 'UserAuthentication', '/t', 'REG_DWORD', '/d', '1', '/f']
    fw_enable_cmd = ['netsh', 'advfirewall', 'firewall', 'set', 'rule', 'group="remote desktop"', 'new', 'enable=yes']

    results = {}
    results["allow"] = run_command(reg_allow_cmd)

    # Only proceed if the main allow command was successful
    if results["allow"]["returncode"] == 0:
        results["nla"] = run_command(reg_nla_cmd)
        results["firewall"] = run_command(fw_enable_cmd)
    else:
        results["nla"] = {"returncode": -10, "stderr": "Skipped: Allow RDP failed."}
        results["firewall"] = {"returncode": -10, "stderr": "Skipped: Allow RDP failed."}

    # Aggregate results
    success = results["allow"]["returncode"] == 0
    message = f"Reg Allow RDP (fDenyTSConnections=0): {'OK' if success else 'FAIL ('+str(results['allow']['returncode'])+')'}. "
    message += f"Reg NLA (UserAuthentication=1): {'OK' if results['nla']['returncode'] == 0 else 'FAIL/SKIP ('+str(results['nla']['returncode'])+')'}. "
    message += f"Firewall Enable Group: {'OK' if results['firewall']['returncode'] == 0 else 'FAIL/SKIP ('+str(results['firewall']['returncode'])+')'}."

    # Append specific errors if any step failed
    all_errors = []
    if results["allow"]["returncode"] != 0: all_errors.append(f"Allow RDP Err: {results['allow']['stderr']}")
    if results["nla"]["returncode"] != 0: all_errors.append(f"NLA Err: {results['nla']['stderr']}")
    if results["firewall"]["returncode"] != 0: all_errors.append(f"Firewall Err: {results['firewall']['stderr']}")
    if all_errors: message += " Errors: " + " | ".join(all_errors)

    status = "success" if success else "failure" # Base overall success on the main 'allow' step
    logger.info(f"Enable RDP Result: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def enable_firewall() -> Dict[str, str]:
    """
    Enables the Windows Firewall for all profiles (Domain, Private, Public).

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info("Attempting to enable Firewall for all profiles...")
    command = ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on']
    result = run_command(command)
    success = result["returncode"] == 0
    status = "success" if success else "failure"
    message = result['stdout'] if success else f"Failed (Code: {result['returncode']}). Error: {result['stderr']}"
    logger.info(f"Enable Firewall Result: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def disable_firewall() -> Dict[str, str]:
    """
    Disables the Windows Firewall for all profiles (Domain, Private, Public). Use with caution!

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.warning("Attempting to DISABLE Firewall for all profiles...")
    command = ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off']
    result = run_command(command)
    success = result["returncode"] == 0
    status = "success" if success else "failure"
    message = result['stdout'] if success else f"Failed (Code: {result['returncode']}). Error: {result['stderr']}"
    logger.warning(f"Disable Firewall Result: {status} - {message}")
    return {"status": status, "message": message}


@mcp.tool()
def enable_uac() -> Dict[str, str]:
    """
    Enables User Account Control (UAC) by setting the EnableLUA registry key to 1.

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info("Attempting to enable UAC (set EnableLUA=1)...")
    reg_cmd = ['reg', 'add', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', '/v', 'EnableLUA', '/t', 'REG_DWORD', '/d', '1', '/f']
    reg_result = run_command(reg_cmd)
    success = reg_result["returncode"] == 0
    status = "success" if success else "failure"
    message = f"Registry Set EnableLUA=1: {'Succeeded' if success else 'Failed (' + str(reg_result['returncode']) + ')'}."
    if not success: message += f" Error: {reg_result['stderr']}"
    logger.info(f"Enable UAC Result: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def disable_uac() -> Dict[str, str]:
    """
    Disables User Account Control (UAC) by setting the EnableLUA registry key to 0. Requires restart.

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.warning("Attempting to disable UAC (set EnableLUA=0)...")
    reg_cmd = ['reg', 'add', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', '/v', 'EnableLUA', '/t', 'REG_DWORD', '/d', '0', '/f']
    reg_result = run_command(reg_cmd)
    success = reg_result["returncode"] == 0
    status = "success" if success else "failure"
    message = f"Registry Set EnableLUA=0: {'Succeeded' if success else 'Failed (' + str(reg_result['returncode']) + ')'}."
    if success: message += " A system restart is required for this change to take full effect."
    else: message += f" Error: {reg_result['stderr']}"
    logger.warning(f"Disable UAC Result: {status} - {message}")
    return {"status": status, "message": message}


@mcp.tool()
def disable_guest_account() -> Dict[str, str]:
    """
    Disables the local Guest account using 'net user Guest /active:no'.

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info("Attempting to disable Guest account...")
    cmd = ['net', 'user', 'Guest', '/active:no']
    result = run_command(cmd)
    success = result["returncode"] == 0
    status = "success" if success else "failure"
    message = f"'net user Guest /active:no': {'Succeeded' if success else 'Failed (' + str(result['returncode']) + ')'}."
    if not success: message += f" Error: {result['stderr']}"
    logger.info(f"Disable Guest Account Result: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def enable_guest_account() -> Dict[str, str]:
    """
    Enables the local Guest account using 'net user Guest /active:yes'. Use with caution.

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.warning("Attempting to enable Guest account...")
    cmd = ['net', 'user', 'Guest', '/active:yes']
    result = run_command(cmd)
    success = result["returncode"] == 0
    status = "success" if success else "failure"
    message = f"'net user Guest /active:yes': {'Succeeded' if success else 'Failed (' + str(result['returncode']) + ')'}."
    if not success: message += f" Error: {result['stderr']}"
    logger.warning(f"Enable Guest Account Result: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def flush_dns_cache() -> Dict[str, str]:
    """
    Flushes the DNS resolver cache using 'ipconfig /flushdns'.

    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info("Attempting to flush DNS cache...")
    cmd = ['ipconfig', '/flushdns']
    result = run_command(cmd)
    # ipconfig /flushdns usually returns 0 even if cache is empty, check stdout message
    success = result["returncode"] == 0 and "Successfully flushed the DNS Resolver Cache" in result["stdout"]
    status = "success" if success else "failure"
    message = f"'ipconfig /flushdns': {'Succeeded' if success else 'Failed (' + str(result['returncode']) + ')'}. Output: {result['stdout']}"
    if result["returncode"] != 0: message += f" Error: {result['stderr']}"
    logger.info(f"Flush DNS Cache Result: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def set_password_policy(min_length: int = 10, history_count: int = 24, max_age: int = 60, min_age: int = 1, complexity_enabled: bool = True) -> Dict[str, str]:
    """
    Configures Windows password policy with customizable settings.
    
    Args:
        min_length: Minimum password length (recommended 8 or more)
        history_count: Number of previous passwords remembered (prevent reuse)
        max_age: Maximum password age in days before requiring change
        min_age: Minimum password age in days before allowing change
        complexity_enabled: Whether to enable password complexity requirements
    
    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info(f"Setting password policy: length={min_length}, history={history_count}, max_age={max_age}, min_age={min_age}, complexity={complexity_enabled}")
    
    # Set minimum password length
    cmd_minpwlen = ['net', 'accounts', f'/minpwlen:{min_length}']
    min_len_result = run_command(cmd_minpwlen)
    
    # Set password history
    cmd_uniquepw = ['net', 'accounts', f'/uniquepw:{history_count}']
    history_result = run_command(cmd_uniquepw)
    
    # Set maximum password age
    cmd_maxpwage = ['net', 'accounts', f'/maxpwage:{max_age}']
    max_age_result = run_command(cmd_maxpwage)
    
    # Set minimum password age
    cmd_minpwage = ['net', 'accounts', f'/minpwage:{min_age}']
    min_age_result = run_command(cmd_minpwage)
    
    # Set password complexity via registry
    # 1 = Enabled, 0 = Disabled
    complexity_value = '1' if complexity_enabled else '0'
    cmd_complexity = ['reg', 'add', r'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', '/v', 'PasswordComplexity', '/t', 'REG_DWORD', '/d', complexity_value, '/f']
    complexity_result = run_command(cmd_complexity)
    
    # Check if all operations were successful
    all_successful = (
        min_len_result["returncode"] == 0 and
        history_result["returncode"] == 0 and
        max_age_result["returncode"] == 0 and
        min_age_result["returncode"] == 0 and
        complexity_result["returncode"] == 0
    )
    
    status = "success" if all_successful else "failure"
    
    # Compile results into a message
    message = f"Password policy set: Length={min_length}, History={history_count}, Max Age={max_age}, Min Age={min_age}, Complexity={'Enabled' if complexity_enabled else 'Disabled'}"
    
    if not all_successful:
        message += "\nErrors encountered: "
        if min_len_result["returncode"] != 0:
            message += f"Min Length: {min_len_result['stderr']} | "
        if history_result["returncode"] != 0:
            message += f"History: {history_result['stderr']} | "
        if max_age_result["returncode"] != 0:
            message += f"Max Age: {max_age_result['stderr']} | "
        if min_age_result["returncode"] != 0:
            message += f"Min Age: {min_age_result['stderr']} | "
        if complexity_result["returncode"] != 0:
            message += f"Complexity: {complexity_result['stderr']}"
    
    logger.info(f"Set password policy: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def set_account_lockout_policy(lockout_threshold: int = 10, lockout_duration: int = 30, reset_count: int = 30) -> Dict[str, str]:
    """
    Configures Windows account lockout policy with customizable settings.
    
    Args:
        lockout_threshold: Number of failed login attempts before account is locked
        lockout_duration: Duration in minutes to lock account after exceeding failed attempts
        reset_count: Time in minutes before the failed login counter resets
    
    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info(f"Setting account lockout policy: threshold={lockout_threshold}, duration={lockout_duration}, reset_count={reset_count}")
    
    # Set lockout threshold
    cmd_threshold = ['net', 'accounts', f'/lockoutthreshold:{lockout_threshold}']
    threshold_result = run_command(cmd_threshold)
    
    # If lockout threshold is set to 0, no lockout occurs, so we can skip the other settings
    if lockout_threshold == 0:
        status = "success" if threshold_result["returncode"] == 0 else "failure"
        message = "Account lockout disabled (threshold set to 0)"
        if threshold_result["returncode"] != 0:
            message += f" Error: {threshold_result['stderr']}"
        logger.info(f"Set account lockout policy: {status} - {message}")
        return {"status": status, "message": message}
    
    # Set lockout duration
    cmd_duration = ['net', 'accounts', f'/lockoutduration:{lockout_duration}']
    duration_result = run_command(cmd_duration)
    
    # Set reset counter
    cmd_reset = ['net', 'accounts', f'/lockoutwindow:{reset_count}']
    reset_result = run_command(cmd_reset)
    
    # Check if all operations were successful
    all_successful = (
        threshold_result["returncode"] == 0 and
        duration_result["returncode"] == 0 and
        reset_result["returncode"] == 0
    )
    
    status = "success" if all_successful else "failure"
    
    # Compile results into a message
    message = f"Account lockout policy set: Threshold={lockout_threshold}, Duration={lockout_duration} min, Reset Count={reset_count} min"
    
    if not all_successful:
        message += "\nErrors encountered: "
        if threshold_result["returncode"] != 0:
            message += f"Threshold: {threshold_result['stderr']} | "
        if duration_result["returncode"] != 0:
            message += f"Duration: {duration_result['stderr']} | "
        if reset_result["returncode"] != 0:
            message += f"Reset Count: {reset_result['stderr']}"
    
    logger.info(f"Set account lockout policy: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def manage_user_account(username: str, force_password_change: bool = True, disable_account: bool = False, set_password: str = None) -> Dict[str, str]:
    """
    Manages a Windows user account with options to force password change, disable account, or set password.
    
    Args:
        username: The Windows username to modify
        force_password_change: Whether to force the user to change password at next logon
        disable_account: Whether to disable the account
        set_password: Optional new password to set for the account (omit to leave unchanged)
    
    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info(f"Managing user account: {username}")
    results = {}
    all_successful = True
    
    # First check if the user exists
    cmd_check = ['net', 'user', username]
    check_result = run_command(cmd_check)
    
    if check_result["returncode"] != 0:
        logger.error(f"User {username} not found or cannot be accessed")
        return {
            "status": "failure", 
            "message": f"User {username} not found or cannot be accessed. Error: {check_result['stderr']}"
        }
    
    # Set password if requested
    if set_password:
        cmd_password = ['net', 'user', username, set_password]
        password_result = run_command(cmd_password)
        results["password"] = password_result
        all_successful = all_successful and (password_result["returncode"] == 0)
    
    # Force password change if requested
    if force_password_change:
        cmd_force_change = ['wmic', 'useraccount', 'where', f'name="{username}"', 'set', 'passwordexpires=true']
        force_change_result = run_command(cmd_force_change)
        results["force_change"] = force_change_result
        all_successful = all_successful and (force_change_result["returncode"] == 0)
        
        # Use WMIC to set the "user must change password at next logon" flag
        cmd_must_change = ['net', 'user', username, '/logonpasswordchg:yes']
        must_change_result = run_command(cmd_must_change)
        results["must_change"] = must_change_result
        all_successful = all_successful and (must_change_result["returncode"] == 0)
    
    # Disable account if requested
    if disable_account:
        cmd_disable = ['net', 'user', username, '/active:no']
        disable_result = run_command(cmd_disable)
        results["disable"] = disable_result
        all_successful = all_successful and (disable_result["returncode"] == 0)
    else:
        # Make sure the account is enabled
        cmd_enable = ['net', 'user', username, '/active:yes']
        enable_result = run_command(cmd_enable)
        results["enable"] = enable_result
        all_successful = all_successful and (enable_result["returncode"] == 0)
    
    status = "success" if all_successful else "failure"
    
    # Compile results into a message
    message = f"User account {username} managed:"
    if set_password:
        message += f" Set new password: {'Success' if results.get('password', {}).get('returncode', 1) == 0 else 'Failed'}"
    
    if force_password_change:
        message += f" Force password change: {'Success' if results.get('force_change', {}).get('returncode', 1) == 0 and results.get('must_change', {}).get('returncode', 1) == 0 else 'Failed'}"
    
    if disable_account:
        message += f" Disable account: {'Success' if results.get('disable', {}).get('returncode', 1) == 0 else 'Failed'}"
    else:
        message += f" Enable account: {'Success' if results.get('enable', {}).get('returncode', 1) == 0 else 'Failed'}"
    
    if not all_successful:
        message += "\nErrors encountered: "
        for key, result in results.items():
            if result["returncode"] != 0:
                message += f"{key}: {result['stderr']} | "
    
    logger.info(f"Managed user account {username}: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def manage_user_groups(username: str, add_to_groups: List[str] = None, remove_from_groups: List[str] = None) -> Dict[str, str]:
    """
    Manages a user's group membership by adding or removing them from specified groups.
    
    Args:
        username: The Windows username to modify
        add_to_groups: List of groups to add the user to
        remove_from_groups: List of groups to remove the user from
    
    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info(f"Managing group membership for user: {username}")
    
    # Default to empty lists if None
    add_to_groups = add_to_groups or []
    remove_from_groups = remove_from_groups or []
    
    # Check if user exists first
    cmd_check = ['net', 'user', username]
    check_result = run_command(cmd_check)
    
    if check_result["returncode"] != 0:
        logger.error(f"User {username} not found or cannot be accessed")
        return {
            "status": "failure", 
            "message": f"User {username} not found or cannot be accessed. Error: {check_result['stderr']}"
        }
    
    results = {"add": {}, "remove": {}}
    all_successful = True
    
    # Add user to specified groups
    for group in add_to_groups:
        cmd_add = ['net', 'localgroup', group, username, '/add']
        add_result = run_command(cmd_add)
        results["add"][group] = add_result
        all_successful = all_successful and (add_result["returncode"] == 0)
    
    # Remove user from specified groups
    for group in remove_from_groups:
        cmd_remove = ['net', 'localgroup', group, username, '/delete']
        remove_result = run_command(cmd_remove)
        results["remove"][group] = remove_result
        all_successful = all_successful and (remove_result["returncode"] == 0)
    
    status = "success" if all_successful else "failure"
    
    # Compile results into a message
    message = f"Group membership for {username} modified:"
    
    # Add operations summary
    if add_to_groups:
        message += "\nAdded to groups: "
        for group, result in results["add"].items():
            success = result["returncode"] == 0
            message += f"{group} ({'Success' if success else 'Failed'}), "
    
    # Remove operations summary
    if remove_from_groups:
        message += "\nRemoved from groups: "
        for group, result in results["remove"].items():
            success = result["returncode"] == 0
            message += f"{group} ({'Success' if success else 'Failed'}), "
    
    # If any operations failed, include error details
    if not all_successful:
        message += "\nErrors encountered: "
        for op_type in ["add", "remove"]:
            for group, result in results[op_type].items():
                if result["returncode"] != 0:
                    message += f"{op_type.capitalize()} to {group}: {result['stderr']} | "
    
    logger.info(f"Managed group membership for {username}: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def manage_windows_service(service_name: str, action: str = "status", startup_type: str = None) -> Dict[str, str]:
    """
    Manages a Windows service by starting, stopping, disabling, or enabling it.
    
    Args:
        service_name: Name of the Windows service to manage
        action: Action to perform: "status", "start", "stop", "restart", or "query"
        startup_type: Sets the startup type: "auto", "demand" (manual), "disabled", or None (don't change)
    
    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info(f"Managing Windows service: {service_name}, action: {action}, startup_type: {startup_type}")
    
    results = {}
    all_successful = True
    
    # Validate inputs
    valid_actions = ["status", "start", "stop", "restart", "query"]
    valid_startup_types = ["auto", "demand", "disabled"]
    
    if action not in valid_actions:
        return {
            "status": "failure",
            "message": f"Invalid action: {action}. Valid actions are: {', '.join(valid_actions)}"
        }
    
    if startup_type is not None and startup_type not in valid_startup_types:
        return {
            "status": "failure",
            "message": f"Invalid startup type: {startup_type}. Valid types are: {', '.join(valid_startup_types)}"
        }
    
    # Check if service exists
    cmd_query = ['sc', 'query', service_name]
    query_result = run_command(cmd_query)
    
    if query_result["returncode"] != 0:
        logger.error(f"Service {service_name} not found or cannot be accessed")
        return {
            "status": "failure", 
            "message": f"Service {service_name} not found or cannot be accessed. Error: {query_result['stderr']}"
        }
    
    # Store the query result
    results["query"] = query_result
    service_info = query_result["stdout"]
    
    # Just return status if that's what was requested
    if action == "status" or action == "query":
        return {
            "status": "success",
            "message": f"Service {service_name} status:\n{service_info}"
        }
    
    # Perform the requested action
    if action == "start":
        cmd_action = ['sc', 'start', service_name]
    elif action == "stop":
        cmd_action = ['sc', 'stop', service_name]
    elif action == "restart":
        # First stop the service
        stop_result = run_command(['sc', 'stop', service_name])
        results["stop"] = stop_result
        all_successful = all_successful and (stop_result["returncode"] == 0)
        
        # Wait a moment for the service to stop
        import time
        time.sleep(2)
        
        # Then start it
        cmd_action = ['sc', 'start', service_name]
    else:
        # This should never happen due to validation
        return {
            "status": "failure",
            "message": f"Invalid action: {action}"
        }
    
    # Execute the action command
    action_result = run_command(cmd_action)
    results["action"] = action_result
    all_successful = all_successful and (action_result["returncode"] == 0)
    
    # Set startup type if requested
    if startup_type is not None:
        cmd_config = ['sc', 'config', service_name, f'start={startup_type}']
        config_result = run_command(cmd_config)
        results["config"] = config_result
        all_successful = all_successful and (config_result["returncode"] == 0)
    
    status = "success" if all_successful else "failure"
    
    # Compile results into a message
    message = f"Service {service_name} management:"
    
    # Action result
    if action == "restart":
        message += f"\nStop: {'Success' if results.get('stop', {}).get('returncode', 1) == 0 else 'Failed'}"
        message += f"\nStart: {'Success' if results.get('action', {}).get('returncode', 1) == 0 else 'Failed'}"
    else:
        message += f"\n{action.capitalize()}: {'Success' if results.get('action', {}).get('returncode', 1) == 0 else 'Failed'}"
    
    # Startup type result
    if startup_type is not None:
        message += f"\nSet startup type to {startup_type}: {'Success' if results.get('config', {}).get('returncode', 1) == 0 else 'Failed'}"
    
    # If any operations failed, include error details
    if not all_successful:
        message += "\nErrors encountered: "
        for key, result in results.items():
            if key != "query" and result["returncode"] != 0:
                message += f"{key}: {result['stderr']} | "
    
    logger.info(f"Managed service {service_name}: {status} - {message}")
    return {"status": status, "message": message}

@mcp.tool()
def harden_insecure_services() -> Dict[str, str]:
    """
    Secures multiple potentially insecure Windows services by disabling them.
    Handles commonly exploited services like Telnet, TFTP, FTP, Remote Registry, etc.
    
    Returns:
        dict: Status dictionary {"status": "success"|"failure", "message": "Details..."}
    """
    logger.info("Starting bulk service hardening process")
    
    # List of potentially dangerous services to disable
    dangerous_services = [
        "TlntSvr",           # Telnet Server
        "FTPSVC",            # FTP Server
        "SMTPSVC",           # SMTP Server
        "SNMPTRAP",          # SNMP Trap Service
        "RemoteRegistry",    # Remote Registry
        "RpcSs",             # Remote Procedure Call
        "UPnPHost",          # UPnP Device Host
        "SSDPSRV",           # SSDP Discovery Service
        "SharedAccess",      # Internet Connection Sharing
        "ShellHWDetection",  # Shell Hardware Detection
        "TrkWks",            # Distributed Link Tracking Client
        "WebClient",         # WebClient service
        "Fax",               # Fax service
        "iPod Service",      # iPod Service
        "WinRM",             # Windows Remote Management
        "wercplsupport",     # Problem Reports and Solutions Control Panel
        "Netlogon"           # NetLogon (If not in domain)
    ]
    
    results = {}
    success_count = 0
    already_disabled_count = 0
    error_count = 0
    
    for service in dangerous_services:
        # First check if service exists
        cmd_query = ['sc', 'query', service]
        query_result = run_command(cmd_query)
        
        # If service doesn't exist, skip it
        if query_result["returncode"] != 0:
            results[service] = {
                "status": "skipped",
                "reason": "Service not found or inaccessible"
            }
            continue
        
        # Check if service is already disabled
        config_query = ['sc', 'qc', service]
        config_result = run_command(config_query)
        
        if "START_TYPE : 4" in config_result["stdout"]:
            results[service] = {
                "status": "already disabled",
                "reason": "Service was already set to disabled"
            }
            already_disabled_count += 1
            continue
        
        # First stop the service
        stop_cmd = ['sc', 'stop', service]
        stop_result = run_command(stop_cmd)
        
        # Then disable it
        disable_cmd = ['sc', 'config', service, 'start=disabled']
        disable_result = run_command(disable_cmd)
        
        if disable_result["returncode"] == 0:
            results[service] = {
                "status": "success",
                "details": "Service stopped and disabled successfully"
            }
            success_count += 1
        else:
            results[service] = {
                "status": "error",
                "details": f"Failed to disable: {disable_result['stderr']}"
            }
            error_count += 1
    
    # Format the results message
    message = f"Service hardening results:\n"
    message += f"• Successfully disabled: {success_count} services\n"
    message += f"• Already disabled: {already_disabled_count} services\n"
    message += f"• Errors encountered: {error_count} services\n\n"
    
    # Add detailed results for each service
    message += "Detailed results:\n"
    for service, result in results.items():
        message += f"{service}: {result['status']}"
        if "reason" in result:
            message += f" - {result['reason']}"
        elif "details" in result:
            message += f" - {result['details']}"
        message += "\n"
    
    status = "success" if error_count == 0 else "partial" if success_count > 0 else "failure"
    
    logger.info(f"Bulk service hardening completed: {status} - Disabled: {success_count}, Already disabled: {already_disabled_count}, Errors: {error_count}")
    return {"status": status, "message": message}

# --- Helper functions for security checks ---

def check_password_policy() -> Dict[str, Any]:
    """
    Checks the current password policy settings without changing them.
    
    Returns:
        dict: Current password policy settings
    """
    logger.info("Checking password policy...")
    
    # Get current password policy
    cmd = ['net', 'accounts']
    result = run_command(cmd)
    
    # Default values
    policy = {
        "min_length": 0,
        "history_count": 0,
        "max_age": 0,
        "min_age": 0,
        "complexity_enabled": False
    }
    
    if result["returncode"] == 0:
        # Parse min length
        min_length_match = re.search(r"Minimum password length\s+:\s+(\d+)", result["stdout"])
        if min_length_match:
            policy["min_length"] = int(min_length_match.group(1))
        
        # Parse history count
        history_match = re.search(r"Length of password history maintained\s+:\s+(\d+)", result["stdout"])
        if history_match:
            policy["history_count"] = int(history_match.group(1))
        
        # Parse max age
        max_age_match = re.search(r"Maximum password age \(days\)\s+:\s+(\d+)", result["stdout"])
        if max_age_match:
            policy["max_age"] = int(max_age_match.group(1))
        
        # Parse min age
        min_age_match = re.search(r"Minimum password age \(days\)\s+:\s+(\d+)", result["stdout"])
        if min_age_match:
            policy["min_age"] = int(min_age_match.group(1))
    
    # Check for password complexity
    reg_cmd = ['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', '/v', 'PasswordComplexity']
    reg_result = run_command(reg_cmd)
    if reg_result["returncode"] == 0 and "0x1" in reg_result["stdout"]:
        policy["complexity_enabled"] = True
    
    # Alternative check for domain machines using SecEdit
    if not policy["complexity_enabled"]:
        complexity_cmd = ['secedit', '/export', '/cfg', 'secpol.cfg', '/quiet']
        run_command(complexity_cmd)
        
        try:
            with open('secpol.cfg', 'r') as f:
                secpol_content = f.read()
                if 'PasswordComplexity = 1' in secpol_content:
                    policy["complexity_enabled"] = True
                    
            # Clean up
            import os
            if os.path.exists('secpol.cfg'):
                os.remove('secpol.cfg')
        except:
            logger.warning("Could not check password complexity via SecEdit")
    
    logger.info(f"Password policy check completed: {policy}")
    return policy


def check_account_lockout() -> Dict[str, Any]:
    """
    Checks the current account lockout policy settings without changing them.
    
    Returns:
        dict: Current account lockout policy settings
    """
    logger.info("Checking account lockout policy...")
    
    # Get current lockout policy
    cmd = ['net', 'accounts']
    result = run_command(cmd)
    
    # Default values
    policy = {
        "threshold": 0,
        "duration": 0,
        "reset_count": 0
    }
    
    if result["returncode"] == 0:
        # Parse lockout threshold
        threshold_match = re.search(r"Lockout threshold\s+:\s+(\d+)", result["stdout"])
        if threshold_match:
            policy["threshold"] = int(threshold_match.group(1))
        
        # Parse lockout duration
        duration_match = re.search(r"Lockout duration \(minutes\)\s+:\s+(\d+)", result["stdout"])
        if duration_match:
            policy["duration"] = int(duration_match.group(1))
        
        # Parse reset count
        reset_match = re.search(r"Lockout observation window \(minutes\)\s+:\s+(\d+)", result["stdout"])
        if reset_match:
            policy["reset_count"] = int(reset_match.group(1))
    
    logger.info(f"Account lockout policy check completed: {policy}")
    return policy


def check_insecure_services() -> Dict[str, Dict[str, Any]]:
    """
    Checks for insecure services without changing them.
    
    Returns:
        dict: Status of potentially insecure services
    """
    logger.info("Checking for insecure services...")
    
    # List of potentially dangerous services to check
    dangerous_services = {
        "TlntSvr": "Telnet Server",
        "FTPSVC": "FTP Server",
        "SMTPSVC": "SMTP Server",
        "SNMPTRAP": "SNMP Trap Service",
        "RemoteRegistry": "Remote Registry",
        "UPnPHost": "UPnP Device Host",
        "SSDPSRV": "SSDP Discovery Service",
        "WebClient": "WebClient service",
        "Fax": "Fax service",
        "WinRM": "Windows Remote Management"
    }
    
    results = {}
    
    for service_name, display_name in dangerous_services.items():
        # Check if service exists
        cmd_query = ['sc', 'query', service_name]
        query_result = run_command(cmd_query)
        
        # Default to not found
        service_status = {
            "found": False,
            "running": False,
            "startup_type": "unknown",
            "display_name": display_name
        }
        
        # If service exists, check its status
        if query_result["returncode"] == 0:
            service_status["found"] = True
            
            # Check if it's running
            if "RUNNING" in query_result["stdout"]:
                service_status["running"] = True
            
            # Check startup type
            config_query = ['sc', 'qc', service_name]
            config_result = run_command(config_query)
            
            if config_result["returncode"] == 0:
                if "AUTO_START" in config_result["stdout"]:
                    service_status["startup_type"] = "auto"
                elif "DEMAND_START" in config_result["stdout"]:
                    service_status["startup_type"] = "manual"
                elif "DISABLED" in config_result["stdout"] or "4" in config_result["stdout"]:
                    service_status["startup_type"] = "disabled"
        
        results[service_name] = service_status
    
    logger.info(f"Insecure services check completed: Found {sum(1 for s in results.values() if s['found'])} services")
    return results


def check_network_security() -> Dict[str, Dict[str, Any]]:
    """
    Checks network security settings without changing them.
    
    Returns:
        dict: Status of network security settings
    """
    logger.info("Checking network security settings...")
    
    results = {}
    
    # Check SMBv1 status - Check multiple methods
    # Method 1: Check registry key
    smb1_reg_cmd = ['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', '/v', 'SMB1']
    smb1_reg_result = run_command(smb1_reg_cmd)
    
    # Method 2: Check Windows Feature status using PowerShell
    smb1_feature_cmd = ['powershell', '-Command', 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State']
    smb1_feature_result = run_command(smb1_feature_cmd)
    
    results["SMBv1"] = {
        "secure": False,
        "recommendation": "Disable SMBv1 protocol which is vulnerable to exploits like WannaCry"
    }
    
    # Check if SMBv1 is disabled through Windows Feature
    if smb1_feature_result["returncode"] == 0 and "Disabled" in smb1_feature_result["stdout"]:
        results["SMBv1"]["secure"] = True
    # If PowerShell check failed, fall back to registry check
    elif smb1_reg_result["returncode"] == 0:
        value_match = re.search(r"SMB1\s+REG_DWORD\s+(0x\d+)", smb1_reg_result["stdout"], re.IGNORECASE)
        if value_match:
            # SMB1 is secure when set to 0x0 (disabled)
            results["SMBv1"]["secure"] = value_match.group(1).lower() == "0x0"
    
    # Check if LLMNR is disabled (Link-Local Multicast Name Resolution)
    llmnr_cmd = ['reg', 'query', r'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', '/v', 'EnableMulticast']
    llmnr_result = run_command(llmnr_cmd)
    
    results["LLMNR"] = {
        "secure": False,
        "recommendation": "Disable LLMNR to prevent potential MitM attacks"
    }
    
    if llmnr_result["returncode"] == 0:
        value_match = re.search(r"EnableMulticast\s+REG_DWORD\s+(0x\d+)", llmnr_result["stdout"], re.IGNORECASE)
        if value_match:
            # LLMNR is secure when set to 0x0 (disabled)
            results["LLMNR"]["secure"] = value_match.group(1).lower() == "0x0"
    
    # Check if NetBIOS is disabled
    netbios_cmd = ['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters', '/v', 'NetbiosOptions']
    netbios_result = run_command(netbios_cmd)
    
    results["NetBIOS"] = {
        "secure": False,
        "recommendation": "Disable NetBIOS to reduce attack surface"
    }
    
    if netbios_result["returncode"] == 0:
        value_match = re.search(r"NetbiosOptions\s+REG_DWORD\s+(0x\d+)", netbios_result["stdout"], re.IGNORECASE)
        if value_match:
            # NetBIOS is secure when set to 0x2 (disabled)
            results["NetBIOS"]["secure"] = value_match.group(1).lower() == "0x2"
    
    # Check NTLM security settings
    ntlm_cmd = ['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa', '/v', 'LmCompatibilityLevel']
    ntlm_result = run_command(ntlm_cmd)
    
    results["NTLM"] = {
        "secure": False,
        "recommendation": "Set NTLM to level 5 (send NTLMv2, refuse LM and NTLM)"
    }
    
    if ntlm_result["returncode"] == 0:
        value_match = re.search(r"LmCompatibilityLevel\s+REG_DWORD\s+(0x\d+)", ntlm_result["stdout"], re.IGNORECASE)
        if value_match:
            # NTLM is secure when set to 0x5 or 0x4
            value = value_match.group(1).lower()
            results["NTLM"]["secure"] = value == "0x5" or value == "0x4"
    
    logger.info(f"Network security check completed: {sum(1 for s in results.values() if s['secure'])}/{len(results)} settings secure")
    return results

# --- Main Execution Block ---
if __name__ == "__main__":
    logger.info("--- Windows Hardening MCP Server ---")
    logger.warning("!!! This server requires Administrator privileges to modify system settings !!!")
    logger.warning("!!! Start this script from a terminal that was 'Run as Administrator' !!!")

    try:
        # Run using the default transport (stdio) which is what Claude Desktop expects
        logger.info("Starting MCP server...")
        mcp.run()

    except PermissionError:
        logger.error("FATAL: Permission denied. This server MUST be run as Administrator.")
    except OSError as e:
        if "address already in use" in str(e):
            logger.error("FATAL: Port is already in use. Is another instance of the server running?")
        else:
            logger.error(f"FATAL: Failed to start server due to OS Error: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"FATAL: An unexpected error occurred during server startup: {e}", exc_info=True)
    finally:
        logger.info("--- Server shutdown ---")