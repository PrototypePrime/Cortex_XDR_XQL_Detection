/*
==============================================================================
CORTEX XDR XQL DETECTION - ACCOUNT MANIPULATION
==============================================================================
Rule: User Added to Admin Group
ID: XQL-ID-001
Author: PrototypePrime
Date: 2025-12-02
MITRE: T1098 (Account Manipulation)
Severity: CRITICAL
==============================================================================

WHAT IT DETECTS:
Identifies when a user is added to the local Administrators group on an endpoint.

THE QUERY:
*/

config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.USER_ACCOUNT 
    and event_sub_type = ENUM.USER_ACCOUNT_MEMBER_ADDED
    and target_object_group_name = "Administrators"
| fields _time, agent_hostname, actor_effective_username, target_object_name
| alter severity = "CRITICAL"

/*
==============================================================================
TUNING
==============================================================================
False Positives:
- Authorized admin activity

Exclusions:
| filter actor_effective_username != "domain_admin"

==============================================================================
TESTING
==============================================================================
Test Command: 
net localgroup Administrators testuser /add

Expected Result:
Alert triggers showing user addition.
==============================================================================
*/
