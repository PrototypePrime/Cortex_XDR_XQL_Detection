/*
==============================================================================
CORTEX XDR XQL DETECTION - DATA EXFILTRATION
==============================================================================
Rule: Large Upload to External IP
ID: XQL-DATA-001
Author: Mathan
Date: 2025-12-02
MITRE: T1048 (Exfiltration)
Severity: MEDIUM
==============================================================================

WHAT IT DETECTS:
Identifies hosts uploading large amounts of data (>100MB) to external destinations.

THE QUERY:
*/

config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_upload > 104857600
| filter action_remote_ip_country != "Reserved"
| fields _time, agent_hostname, action_remote_ip, action_upload
| alter severity = "MEDIUM"

/*
==============================================================================
TUNING
==============================================================================
False Positives:
- Backup jobs
- Video calls

Exclusions:
| filter action_remote_ip != "backup_server_ip"

==============================================================================
TESTING
==============================================================================
Test Command: 
Upload 150MB file to external server.

Expected Result:
Alert triggers showing upload size.
==============================================================================
*/
