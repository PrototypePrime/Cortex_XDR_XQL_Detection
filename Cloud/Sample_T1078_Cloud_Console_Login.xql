/*
==============================================================================
CORTEX XDR XQL DETECTION - CLOUD CONSOLE LOGIN
==============================================================================
Rule: Root/Admin Console Login
ID: XQL-CLOUD-001
Author: Mathan
Date: 2025-12-02
MITRE: T1078 (Valid Accounts)
Severity: MEDIUM
==============================================================================

WHAT IT DETECTS:
Identifies logins to the cloud management console using the root account
or high-privilege admin accounts.

THE QUERY:
*/

config case_sensitive = false timeframe = 24h
| dataset = cloud_audit_logs
| filter event_name = "ConsoleLogin" 
    and (user_identity_type = "Root" or user_name contains "admin")
| fields _time, user_name, source_ip_address, user_agent
| alter severity = "MEDIUM"

/*
==============================================================================
TUNING
==============================================================================
False Positives:
- Legitimate admin activity (verify with change records)

Exclusions:
| filter source_ip_address != "1.2.3.4" (Corporate VPN)

==============================================================================
TESTING
==============================================================================
Test Command: 
Login to AWS/Azure console with root account.

Expected Result:
Alert triggers showing the login event.
==============================================================================
*/
