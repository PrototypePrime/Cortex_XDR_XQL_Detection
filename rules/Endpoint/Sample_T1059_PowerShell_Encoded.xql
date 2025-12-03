/*
==============================================================================
CORTEX XDR XQL DETECTION - POWERSHELL ENCODED COMMAND
==============================================================================
Rule: Suspicious PowerShell Execution with Encoded Commands
ID: XQL-ENDPOINT-001
Author: Mathan
Date: 2025-12-02
MITRE: T1059.001 (Command and Scripting Interpreter: PowerShell)
Severity: HIGH

MITRE Tactic: Execution
Data Source: Endpoint Process Telemetry
XDR Event Type: PROCESS_LAUNCH
==============================================================================

WHAT IT DETECTS:
Detects PowerShell execution with encoded commands (-encodedcommand or -enc),
commonly used by attackers to obfuscate malicious scripts and evade 
detection mechanisms.

ATTACK SCENARIO:
1. Attacker gains initial access (phishing, exploit)
2. Executes PowerShell with base64-encoded payload
3. Encoded command downloads/executes malware
4. Establishes persistence or C2 communication

==============================================================================
*/

-- XQL QUERY
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.PROCESS_LAUNCH
    and actor_process_image_name ~= "powershell.exe"
    and (actor_process_command_line contains "-encodedcommand"
         or actor_process_command_line contains "-enc"
         or actor_process_command_line contains "-e ")
| filter actor_effective_username != "SYSTEM"
    and actor_process_image_path !~= "c:\\\\windows\\\\system32\\\\windowspowershell"
| fields 
    _time,
    agent_hostname,
    actor_effective_username,
    actor_process_image_name,
    actor_process_command_line,
    causality_actor_process_image_name,
    causality_actor_process_command_line
| alter 
    severity = "HIGH",
    detection_name = "T1059.001 - PowerShell Encoded Command Execution"

/*
==============================================================================
QUERY EXPLANATION
==============================================================================
1. Filter for PROCESS_LAUNCH events
2. Identify PowerShell.exe executions
3. Check for encoded command parameters (-enc, -encodedcommand, -e)
4. Exclude SYSTEM account (common for legitimate automation)
5. Exclude PowerShell from System32 (reduce FPs from Windows updates)
6. Extract relevant fields for investigation
7. Set severity and detection name

Key XDR Fields:
- actor_process_*: The PowerShell process
- causality_actor_process_*: Parent process (often cmd.exe, wscript, etc.)
- agent_hostname: Affected endpoint
- actor_effective_username: User context

==============================================================================
TUNING & OPTIMIZATION
==============================================================================
Known False Positives:
- Windows Update scripts
- Azure/Office 365 automation agents
- Legitimate admin tools (SCCM, Intune)
- Monitoring agents

Exclusions (add to filter):
and actor_process_image_path not in (
    "c:\\\\program files\\\\microsoft\\\\azure\\\\*",
    "c:\\\\program files (x86)\\\\microsoft intune\\\\*",
    "c:\\\\windows\\\\ccm\\\\*"
)

and causality_actor_process_image_name not in (
    "c:\\\\windows\\\\system32\\\\services.exe",
    "c:\\\\program files\\\\windows defender\\\\msmpeng.exe"
)

and agent_hostname not in (
    "build-server-01",
    "automation-host-*"
)

Threshold Recommendations:
- Leave at 1 occurrence threshold
- Tune based on legitimate automation in environment

==============================================================================
TESTING & VALIDATION
==============================================================================
Test Command (run in elevated PowerShell):
powershell.exe -encodedcommand "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJwBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgBUAGUAcwB0ACIAJwA="

# This decodes to: Invoke-Expression 'Write-Host "Test"'

Expected Result:
- XDR alert showing PowerShell execution
- Command line contains -encodedcommand
- Hostname and username visible
- Parent process captured

==============================================================================
RESPONSE & INVESTIGATION
==============================================================================
Severity: HIGH

Triage Steps:
1. Decode the base64 command and analyze
2. Check parent process legitimacy (wscript/cmd is suspicious)
3. Review process tree/causality chain
4. Check for network connections from PowerShell
5. Search for persistence mechanisms

Investigation in XDR:

Step 1: Decode Command
# Copy base64 string from command line
# Use: https://www.base64decode.org/ or PowerShell:
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<base64>"))

Step 2: Process Tree Analysis
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter agent_hostname = "<affected_host>"
    and causality_actor_process_execution_id = "<process_id>"
| fields _time, actor_process_image_name, actor_process_command_line

Step 3: Network Activity Check
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
    and agent_hostname = "<affected_ host>"
    and actor_process_image_name ~= "powershell.exe"
| fields action_remote_ip, action_remote_port,dst_action_external_hostname

Step 4: File Operations
config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.FILE
    and agent_hostname = "<affected_host>"
    and actor_process_image_name ~= "powershell.exe"
| fields action_file_path, action_file_name

Investigation Questions:
- What is the decoded PowerShell command doing?
- Is the parent process legitimate?
- Was this executed during business hours?
- Does the user recognize this activity?
- Are there subsequent malicious activities?

Immediate Actions:
- Isolate endpoint if confirmed malicious
- Terminate PowerShell process
- Scan endpoint with updated AV signatures
- Review user account for compromise
- Check for lateral movement indicators

Escalation Criteria:
- Downloads executables from internet
- Connects to known C2 infrastructure
- Modifies registry for persistence
- Accesses LSASS orSystem files 
- Executed outside business hours

==============================================================================
BIOC RULE CONFIGURATION
==============================================================================
BIOC Rule Settings:
- Name: T1059.001 - PowerShell Encoded Command
- Severity: High
- Scope: All endpoints
- Response Actions:
  ✓ Create incident
  ⚠️ Isolate endpoint (manual review recommended)
  ⚠️ Block process (use caution - may break legitimate tools)

==============================================================================
CORRELATION WITH OTHER DETECTIONS
==============================================================================
Related XQL Rules:
- XQL-ENDPOINT-002: PowerShell Download/Execute Pattern
- XQL-ENDPOINT-003: Suspicious Process Injection
- XQL-NETWORK-001: PowerShell C2 Beaconing
- XQL-PERSIST-001: Registry Run Key Persistence

Attack Chain Detection:
# Look for full attack chain
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter agent_hostname = "<affected_host>"
    and event_type in (ENUM.PROCESS_LAUNCH, ENUM.NETWORK, ENUM.FILE)
| fields _time, event_type, actor_process_image_name, action

==============================================================================
REFERENCES & DOCUMENTATION
==============================================================================
MITRE ATT&CK:
- https://attack.mitre.org/techniques/T1059/001/

Cortex XDR Documentation:
- https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/investigation/xql-reference

PowerShell Obfuscation:
- https://www.fireeye.com/blog/threat-research/2018/07/obfuscated-malicious-powershell.html

==============================================================================
CHANGE LOG
==============================================================================
Version 1.0 - 2025-12-02 - PrototypePrime
- Initial rule creation
- Tested on 30 days of XDR data

==============================================================================
METADATA TAGS
==============================================================================
Platform: Cortex XDR
Data Source: Endpoint Process Telemetry
Detection Type: Behavioral
Confidence: High
MITRE Tactic: Execution
Environment: Production
Status: Active

==============================================================================
*/
