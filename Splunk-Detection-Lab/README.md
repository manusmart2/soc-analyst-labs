# Splunk Detection Engineering Lab

Developed **15 Splunk detection rules** mapped to MITRE ATT&CK techniques for common attack patterns seen in SOC operations.

## Objectives

- Create high-fidelity detection rules for authentication, execution, and persistence
- Map each detection to MITRE ATT&CK
- Define alert severity and investigation procedures
- Build dashboards for SOC visibility

## Skills Demonstrated

- Splunk SPL query development
- Detection engineering
- MITRE ATT&CK mapping
- Alert triage documentation

## Detections Overview

| # | Detection | MITRE | Severity | File |
|---|-----------|-------|----------|------|
| 1 | Multiple Failed Logins | T1110 | Medium | [01_failed_logins.spl](detections/01_failed_logins.spl) |
| 2 | Brute Force Attack | T1110.001 | High | [02_brute_force.spl](detections/02_brute_force.spl) |
| 3 | PowerShell Execution | T1059.001 | Medium | [03_powershell_execution.spl](detections/03_powershell_execution.spl) |
| 4 | Encoded PowerShell | T1059.001 | High | [04_encoded_powershell.spl](detections/04_encoded_powershell.spl) |
| 5 | New Administrator Account | T1136.001 | High | [05_new_admin_account.spl](detections/05_new_admin_account.spl) |
| 6 | USB Device Insertion | T1091 | Low | [06_usb_insertion.spl](detections/06_usb_insertion.spl) |
| 7 | RDP Login | T1021.001 | Medium | [07_rdp_login.spl](detections/07_rdp_login.spl) |
| 8 | Suspicious Process Execution | T1204 | Medium | [08_suspicious_process.spl](detections/08_suspicious_process.spl) |
| 9 | Credential Dumping (LSASS) | T1003.001 | Critical | [09_lsass_access.spl](detections/09_lsass_access.spl) |
| 10 | Service Installation | T1543.003 | High | [10_service_install.spl](detections/10_service_install.spl) |
| 11 | Registry Run Key Persistence | T1547.001 | High | [11_registry_run_key.spl](detections/11_registry_run_key.spl) |
| 12 | WMI Process Creation | T1047 | Medium | [12_wmi_execution.spl](detections/12_wmi_execution.spl) |
| 13 | Lateral Movement (SMB) | T1021.002 | High | [13_lateral_movement_smb.spl](detections/13_lateral_movement_smb.spl) |
| 14 | After-Hours Login | T1078 | Medium | [14_after_hours_login.spl](detections/14_after_hours_login.spl) |
| 15 | Disabled Account Login | T1078 | High | [15_disabled_account_login.spl](detections/15_disabled_account_login.spl) |

## Detection Template

Each detection follows this structure:

```
Name:        [Detection Name]
Description: [What it detects]
MITRE:       [Technique ID and name]
Severity:    [Low / Medium / High / Critical]
Data Source: [Windows Security / Sysmon / etc.]
False Positives: [Known FP scenarios]
Investigation Steps:
  1. Identify affected host and user
  2. Correlate with adjacent events
  3. Check for follow-on activity
  4. Escalate if confirmed malicious
```

## Dashboard Panels

See [dashboards/dashboard-spec.md](dashboards/dashboard-spec.md) for panel specifications.

Recommended panels:
- Authentication failures (24h trend)
- Top failed login sources
- PowerShell executions by user
- New accounts created (7d)
- Critical severity alert queue

## How to Deploy

1. Open Splunk Search & Reporting
2. Paste SPL from `detections/` folder
3. **Save As → Alert** with appropriate schedule (e.g., every 15 min)
4. Set trigger condition (e.g., `number of results > 0`)
5. Configure email/Slack notification
6. Document in your runbook

## Sample Alert Configuration

| Setting | Value |
|---------|-------|
| Schedule | Cron: `*/15 * * * *` |
| Trigger | Number of results > 0 |
| Throttle | 1 hour per host |
| Severity | Per detection table above |

## Resume Bullet

> Developed Splunk detection rules and dashboards to identify brute-force attacks, PowerShell abuse, account creation, and suspicious authentication events.

## Related Projects

- [SOC Home Lab](../SOC-Home-Lab/) — Lab environment for testing detections
- [Threat Hunting](../Threat-Hunting/) — Proactive hunts using similar queries
- [Incident Response](../Incident-Response/) — IR workflow when alerts fire
