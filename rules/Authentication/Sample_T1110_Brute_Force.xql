/*
==============================================================================
CORTEX XDR XQL DETECTION - BRUTE FORCE
==============================================================================
Rule: Multiple Failed Logins from Single Source
ID: XQL-AUTH-001
Author: Mathan
Date: 2025-12-02
MITRE: T1110 (Brute Force)
Severity: HIGH
==============================================================================

WHAT IT DETECTS:
Identifies a single source IP attempting to login to multiple accounts or
failing multiple times for a single account within a short window.

THE QUERY:
*/

config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.LOGIN and action_result = ENUM.FAILURE
| comp count(action_result) as failure_count by action_remote_ip, actor_effective_username
| filter failure_count > 10
| alter severity = "HIGH"

/*
==============================================================================
TUNING
==============================================================================
False Positives:
- Users forgetting passwords
- Service accounts with expired credentials

Exclusions:
| filter actor_effective_username != "known_service_account"

==============================================================================
TESTING
==============================================================================
Test Command: 
Attempt 15 failed logins to a test account.

Expected Result:
Alert triggers showing the source IP and username.
==============================================================================
*/
