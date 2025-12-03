/*
==============================================================================
CORTEX XDR DETECTION TEMPLATE
==============================================================================
Rule: [Name - e.g., "Suspicious PowerShell Encoded Command"]
ID: XQL-[###]
Author: [Your Name]
Date: [YYYY-MM-DD]
MITRE: [T####] [Technique Name]
Severity: [LOW | MEDIUM | HIGH | CRITICAL]
==============================================================================
*/

-- WHAT IT DETECTS:
-- [Brief 1-line description of what this catches]

-- THE QUERY:
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.PROCESS_LAUNCH
    and actor_process_image_name ~= "powershell.exe"
    and actor_process_command_line contains "-encodedcommand"
| fields _time, agent_hostname, actor_effective_username, 
         actor_process_command_line
| alter severity = "HIGH"

/*
==============================================================================
TUNING
==============================================================================
False Positives:
- [List known FPs - e.g., "Admin automation scripts"]

Exclusions (add to query if needed):
and actor_effective_username != "service_account"
and agent_hostname !~= "admin-workstation"

==============================================================================
TESTING
==============================================================================
Test Command:
powershell.exe -encodedcommand JABh... (base64 encoded)

Expected: Should trigger alert with user + hostname details

==============================================================================
RESPONSE
==============================================================================
1. Verify user account legitimacy
2. Decode the base64 command and analyze
3. Check parent process (should NOT be suspicious)
4. Escalate if unknown parent or external download activity

References:
- https://attack.mitre.org/techniques/T####/
==============================================================================
*/
