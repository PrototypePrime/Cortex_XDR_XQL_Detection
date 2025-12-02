/*
==============================================================================
CORTEX XDR XQL DETECTION - C2 TRAFFIC
==============================================================================
Rule: High Frequency Connections to Rare External IP
ID: XQL-NET-001
Author: PrototypePrime
Date: 2025-12-02
MITRE: T1071 (Application Layer Protocol)
Severity: HIGH
==============================================================================

WHAT IT DETECTS:
Identifies internal hosts making frequent connections to an external IP
that is not commonly accessed by other hosts.

THE QUERY:
*/

config case_sensitive = false timeframe = 1h
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_local_ip != null and action_remote_ip != null
| filter action_remote_ip_country != "Reserved"
| comp count() as conn_count by action_local_ip, action_remote_ip
| filter conn_count > 50
| alter severity = "HIGH"

/*
==============================================================================
TUNING
==============================================================================
False Positives:
- CDN traffic
- Software updates

Exclusions:
| filter action_remote_ip not in ("8.8.8.8", "1.1.1.1")

==============================================================================
TESTING
==============================================================================
Test Command: 
Generate 60 HTTP requests to an external IP in 1 hour.

Expected Result:
Alert triggers for the source host.
==============================================================================
*/
