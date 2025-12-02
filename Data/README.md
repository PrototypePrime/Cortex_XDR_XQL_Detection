# Data Detections

Detection rules for data exfiltration and loss.

## 🎯 What Goes Here
- Large uploads
- USB data transfer
- Sensitive file access
- Cloud storage exfiltration

## 🔍 Common MITRE Techniques
| ID | Technique | Description |
|----|-----------|-------------|
| **T1048** | Exfiltration Over Alternative Protocol | FTP/SSH exfil |
| **T1052** | Exfiltration Over Physical Medium | USB theft |

## 🚀 Sample Detection
See `Sample_T1048_Data_Exfiltration.xql` for a production-ready example.
