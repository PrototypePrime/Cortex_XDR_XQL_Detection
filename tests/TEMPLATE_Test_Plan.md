# Detection Test Plan

**Detection Name:** [Name]
**Date:** [YYYY-MM-DD]

---

## 1. Test Objective
*Verify that the detection logic accurately identifies the malicious behavior while minimizing false positives.*

## 2. Test Scenarios

### Scenario A: True Positive (The Attack)
* **Description:** Simulate the exact attack technique.
* **Tool:** Atomic Red Team / Manual Script
* **Command:**
  ```powershell
  [Insert command here]
  ```
* **Expected Result:** Alert triggers with Severity [High].

### Scenario B: False Positive (Benign Activity)
* **Description:** Simulate normal business activity that looks similar.
* **Command:**
  ```powershell
  [Insert command here]
  ```
* **Expected Result:** Alert does NOT trigger (or triggers Low severity if tuning is needed).

## 3. Execution Log

| Date | Tester | Scenario | Result (Pass/Fail) | Notes |
|------|--------|----------|--------------------|-------|
|      |        | A        |                    |       |
|      |        | B        |                    |       |

## 4. Tuning Actions
*List any exclusions or threshold adjustments made based on testing.*
