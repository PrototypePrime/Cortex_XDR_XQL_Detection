# Network Detections

Detection rules for network traffic anomalies and C2 communication.

## 🎯 What Goes Here
- C2 beaconing
- Port scanning
- Lateral movement (SMB/RDP)
- Data exfiltration
- DNS tunneling

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1071** | Application Layer Protocol | C2 over HTTP/DNS |
| **T1046** | Network Service Scanning | Port scans |
| **T1571** | Non-Standard Port | C2 on weird ports |

## 🚀 Sample Detection
See `Sample_T1071_C2_Traffic.xql` for a production-ready example.
