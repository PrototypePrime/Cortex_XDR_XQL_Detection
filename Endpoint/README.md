# Endpoint Detections

Detection rules for host-based threats and malware execution.

## 🎯 What Goes Here
- Malware execution
- Process injection
- PowerShell/CMD abuse
- Ransomware behavior
- Persistence mechanisms

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1059** | Command and Scripting Interpreter | PowerShell, Bash abuse |
| **T1055** | Process Injection | DLL injection |
| **T1003** | OS Credential Dumping | LSASS dumping |

## 🚀 Sample Detection
See `Sample_T1059_PowerShell_Encoded.xql` for a production-ready example.
