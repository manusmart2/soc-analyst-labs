# IR-2025-001: Phishing to Full Compromise

## Incident Summary

| Field | Value |
|-------|-------|
| **Incident ID** | IR-2025-001 |
| **Title** | Phishing Email Leading to Endpoint Compromise |
| **Severity** | Critical |
| **Status** | Closed |
| **Reported By** | Splunk Alert + User Report |
| **Date** | 2025-03-15 |

## Executive Summary

An employee in the Finance department received a phishing email impersonating a vendor invoice. After clicking the malicious link and entering credentials, the attacker gained access to the workstation. Subsequent investigation revealed PowerShell execution, registry persistence, outbound C2 communication, and an attempted LSASS credential dump. The host was isolated within 2 hours of initial alert. No lateral movement or data exfiltration was confirmed.

## Attack Chain

```
Phishing Email (T1566.002)
       ↓
Credential Harvest (T1078)
       ↓
PowerShell Execution (T1059.001)
       ↓
Persistence — Registry Run Key (T1547.001)
       ↓
Outbound C2 Connection (T1071.001)
       ↓
Credential Dumping Attempt (T1003.001)
       ↓
IOC Creation & Containment
       ↓
Host Isolation & Recovery
```

## Timeline

| Time (UTC) | Event | Source | Details |
|------------|-------|--------|---------|
| 08:05 | Phishing email delivered | Email Gateway | Invoice-themed, SPF fail |
| 08:12 | User clicked malicious URL | Proxy | `secure-pay-invoice.com/login` |
| 08:12 | 12 failed login attempts (attacker) | Win Event 4625 | Source: 185.220.101.45 |
| 08:45 | PowerShell execution | Sysmon EID 1 | Encoded command detected |
| 08:46 | cmd.exe spawned | Sysmon EID 1 | Parent: powershell.exe |
| 09:00 | New local admin created | Win Event 4720 | Account: `evil_admin` |
| 09:15 | Malicious service installed | Win Event 7045 | `EvilService` |
| 09:30 | Outbound C2 connection | Firewall | Dest: 185.220.101.45:443 |
| 10:00 | LSASS access detected | Sysmon EID 10 | Source: suspicious.exe |
| 10:15 | Splunk alert fired | SIEM | Encoded PowerShell + New Admin |
| 10:30 | IR escalated, host isolated | Manual | Network cable disconnected |
| 11:00 | Forensic image acquired | IR Team | Disk image saved |
| 14:00 | Host reimaged | IT | Clean Windows install |
| 16:00 | Incident closed | IR Lead | Monitoring enhanced |

## Root Cause

1. **Initial access:** User clicked phishing link despite external email banner
2. **Credential compromise:** Credentials entered on fake login page
3. **Detection gap:** Phishing URL not blocked (domain registered 3 days prior, not in threat feeds)

## Indicators of Compromise

```
# File Hashes
SHA256: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456 (malware.exe)

# IPs
185.220.101.45 (C2 / attacker)

# Domains
malicious-invoice.net
secure-pay-invoice.com

# URLs
hxxps://legit-vendor.secure-pay-invoice.com/login

# Accounts
evil_admin (created by attacker)
jsmith (compromised credentials — reset)

# Registry
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater = C:\Users\Public\malware.exe

# Services
EvilService → C:\Users\Public\malware.exe
```

## MITRE ATT&CK Mapping

| Stage | Technique | ID |
|-------|-----------|-----|
| Initial Access | Spearphishing Link | T1566.002 |
| Execution | PowerShell | T1059.001 |
| Persistence | Registry Run Keys | T1547.001 |
| Persistence | Windows Service | T1543.003 |
| Privilege Escalation | Create Account | T1136.001 |
| Credential Access | LSASS Memory | T1003.001 |
| Command and Control | HTTPS | T1071.001 |

## Containment Actions

- [x] Host `FINANCE-PC-01` isolated from network (10:30 UTC)
- [x] Account `evil_admin` disabled and deleted
- [x] `jsmith` credentials reset, forced password change
- [x] Domains and IPs blocked at firewall and proxy
- [x] File hash blocked on EDR
- [x] Email quarantined across organization

## Eradication & Recovery

- [x] Forensic disk image acquired before reimage
- [x] Host reimaged with clean Windows 11 build
- [x] Sysmon and EDR reinstalled
- [x] User retrained on phishing identification

## Recommendations

| Priority | Recommendation |
|----------|----------------|
| High | Enable DMARC `p=reject` for company domain |
| High | Deploy URL filtering with newly-registered-domain category |
| Medium | Add encoded PowerShell detection to production SIEM |
| Medium | Implement phishing simulation program (quarterly) |
| Low | Review finance team email banner effectiveness |

## Evidence References

- Phishing case: [PHISH-2025-001](../Phishing-Investigation/case-studies/case-01-invoice-phish.md)
- Splunk detections: [04_encoded_powershell.spl](../Splunk-Detection-Lab/detections/04_encoded_powershell.spl), [05_new_admin_account.spl](../Splunk-Detection-Lab/detections/05_new_admin_account.spl)
- Sample logs: [sample_security.log](../Python-Security-Scripts/data/sample_security.log)

## Lessons Learned

- **What worked:** Splunk correlated encoded PowerShell + new admin within 15 minutes; IR isolation was fast
- **What to improve:** Phishing URL was not blocked proactively; user training needs reinforcement for finance team
