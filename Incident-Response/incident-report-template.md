# Incident Report Template

## Incident Summary

| Field | Value |
|-------|-------|
| **Incident ID** | IR-YYYY-### |
| **Title** | [Brief title] |
| **Severity** | Low / Medium / High / Critical |
| **Status** | Open / Contained / Closed |
| **Reported By** | [User / Alert / Hunt] |
| **Assigned Analyst** | [Name] |
| **Date Opened** | YYYY-MM-DD HH:MM UTC |
| **Date Closed** | YYYY-MM-DD HH:MM UTC |

## Executive Summary

[2-3 paragraph summary for management: what happened, impact, current status]

## Timeline

| Time (UTC) | Event | Source | Evidence |
|------------|-------|--------|----------|
| | Initial phishing email received | Email gateway | MSG-001 |
| | User clicked malicious link | Proxy logs | URL-001 |
| | PowerShell execution detected | Sysmon EID 1 | LOG-001 |
| | Persistence mechanism created | Sysmon EID 13 | LOG-002 |
| | Outbound C2 connection | Firewall | NET-001 |
| | Credential dumping attempt | Sysmon EID 10 | LOG-003 |
| | Alert escalated to IR | Splunk | ALERT-001 |
| | Host isolated | EDR/Manual | ACT-001 |

## Scope

### Affected Systems
- [ ] Hostname, IP, role

### Affected Users
- [ ] Username, department

### Data Impact
- [ ] No data exfiltration confirmed
- [ ] Potential data access: [describe]

## Root Cause

[What allowed the incident to occur? e.g., user clicked phishing link, missing detection rule]

## Indicators of Compromise

```
# File Hashes
SHA256: 

# IPs


# Domains


# URLs


# Email
From: 
Subject: 

# Accounts
Created: 
Compromised: 
```

## MITRE ATT&CK Mapping

| Stage | Technique | ID | Evidence |
|-------|-----------|-----|----------|
| Initial Access | Phishing | T1566.002 | Email sample |
| Execution | PowerShell | T1059.001 | Sysmon log |
| Persistence | Registry Run Key | T1547.001 | Sysmon EID 13 |
| C2 | Application Layer Protocol | T1071.001 | Firewall log |
| Credential Access | LSASS Memory | T1003.001 | Sysmon EID 10 |

## Actions Taken

### Containment
- [ ] Host isolated from network
- [ ] Malicious accounts disabled
- [ ] IOCs blocked at firewall/proxy/email gateway

### Eradication
- [ ] Malware removed
- [ ] Persistence mechanisms cleared
- [ ] Compromised credentials reset

### Recovery
- [ ] System reimaged/restored
- [ ] Enhanced monitoring enabled
- [ ] User notified and retrained

## Recommendations

1. [Short-term]
2. [Medium-term]
3. [Long-term]

## Lessons Learned

[What went well, what to improve]
