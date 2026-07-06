# Threat Hunting

Performed proactive threat hunting in Splunk by analyzing endpoint and authentication logs for attacker behaviors.

## Objectives

- Develop hypothesis-driven hunt queries
- Search for attacker TTPs before alerts fire
- Document hunt methodology, findings, and recommendations
- Map hunts to MITRE ATT&CK

## Skills Demonstrated

- Hypothesis-driven threat hunting
- Splunk advanced SPL
- Log correlation across data sources
- Hunt report documentation

## Hunt Catalog

| # | Hunt | Hypothesis | MITRE | Query |
|---|------|------------|-------|-------|
| 1 | Encoded PowerShell | Attackers use obfuscated PS to evade AV | T1059.001 | [hunt-01-encoded-powershell.spl](hunts/hunt-01-encoded-powershell.spl) |
| 2 | New Local Admin | Persistence via privileged account | T1136.001 | [hunt-02-new-local-admin.spl](hunts/hunt-02-new-local-admin.spl) |
| 3 | WMI Execution | Lateral movement via WMI | T1047 | [hunt-03-wmi-execution.spl](hunts/hunt-03-wmi-execution.spl) |
| 4 | RDP Activity | Unauthorized remote access | T1021.001 | [hunt-04-rdp-activity.spl](hunts/hunt-04-rdp-activity.spl) |
| 5 | Credential Dumping | LSASS access for credential theft | T1003.001 | [hunt-05-credential-dumping.spl](hunts/hunt-05-credential-dumping.spl) |
| 6 | Lateral Movement | SMB admin share connections | T1021.002 | [hunt-06-lateral-movement.spl](hunts/hunt-06-lateral-movement.spl) |

## Hunt Methodology

```
1. HYPOTHESIS — Define attacker behavior to search for
       ↓
2. DATA — Identify required log sources (Sysmon, WinEvent, NetFlow)
       ↓
3. HUNT — Run SPL across historical data (7-30 days)
       ↓
4. ANALYZE — Triage results, eliminate false positives
       ↓
5. DOCUMENT — Record findings, IOCs, recommendations
       ↓
6. DETECT — Convert confirmed hunts into scheduled alerts
```

## Sample Hunt Report Template

See [hunt-report-template.md](hunt-report-template.md)

## Example Hunt: Encoded PowerShell

### Hypothesis
Attackers executing obfuscated PowerShell commands to download secondary payloads or establish C2.

### Data Sources
- Sysmon Event ID 1 (Process Creation)
- Windows Security Event ID 4688

### Results
| Host | User | CommandLine | Verdict |
|------|------|-------------|---------|
| WIN10-01 | jsmith | powershell -enc SQBFAFg... | **True Positive** — matched IR case |
| WIN10-05 | admin | powershell -enc (legitimate script) | False Positive — SCCM deployment |

### Outcome
- 1 true positive referred to Incident Response
- Detection rule created: [04_encoded_powershell.spl](../Splunk-Detection-Lab/detections/04_encoded_powershell.spl)

## Resume Bullet

> Performed proactive threat hunting in Splunk by analyzing endpoint and authentication logs for attacker behaviors.

## Related Projects

- [Splunk Detection Lab](../Splunk-Detection-Lab/) — Convert hunts to detections
- [SOC Home Lab](../SOC-Home-Lab/) — Generate hunt data via Atomic Red Team
- [Incident Response](../Incident-Response/) — Escalate hunt findings
