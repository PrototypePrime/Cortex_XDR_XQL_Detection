/*
==============================================================================
CORTEX XDR BIOC RULE TEMPLATE
Framework: MITRE ATT&CK / BIOC
==============================================================================
Rule Name: [Technique Name] - [Specific Behavior]
Author: [Your Name]
Date: [YYYY-MM-DD]
Version: 1.0

MITRE ATT&CK:
- Tactic: [TA####] [Tactic Name]
- Technique: [T####] [Technique Name]
- Sub-technique: [T####.###] [Name]

Severity: [Low | Medium | High | Critical]
Status: [Development | Staging | Production]

Description:
[Detailed description of the detection logic and the threat it addresses.]

Data Source:
- Dataset: [xdr_data]
- Event Type: [PROCESS_LAUNCH | FILE | NETWORK | REGISTRY]
==============================================================================
*/

// --- THE QUERY ---
config case_sensitive = false timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.PROCESS_LAUNCH
    and actor_process_image_name ~= "powershell.exe"
    and actor_process_command_line contains "-enc"
| fields _time, agent_hostname, actor_process_command_line, actor_effective_username, actor_process_image_path

// --- ENRICHMENT (Virtual Fields) ---
| alter 
    mitre_technique_id = "T1059.001",
    severity = "Medium",
    rule_name = "Suspicious PowerShell Execution"
