/*
==============================================================================
CORTEX XDR XQL DETECTION - PHISHING EMAIL
==============================================================================
Rule: Suspicious Email Attachment
ID: XQL-MAIL-001
Author: Mathan
Date: 2025-12-02
MITRE: T1566 (Phishing)
Severity: HIGH
==============================================================================

WHAT IT DETECTS:
Identifies emails containing suspicious attachment types (exe, scr, vbs).

THE QUERY:
*/

config case_sensitive = false timeframe = 24h
| dataset = email_data
| filter attachment_name ~= ".*\.(exe|scr|vbs|js|bat)$"
| fields _time, sender, recipient, subject, attachment_name
| alter severity = "HIGH"

/*
==============================================================================
TUNING
==============================================================================
False Positives:
- IT scripts sent via email

Exclusions:
| filter sender != "it-support@internal.com"

==============================================================================
TESTING
==============================================================================
Test Command: 
Send email with .exe attachment to test account.

Expected Result:
Alert triggers showing sender and attachment.
==============================================================================
*/
