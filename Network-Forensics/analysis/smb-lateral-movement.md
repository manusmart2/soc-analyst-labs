# SMB Lateral Movement Analysis

## Hypothesis

Compromised host moving laterally via SMB admin shares ($ADMIN$, C$).

## Wireshark Filters

```
smb2 || smb
smb2.tree contains "IPC" || smb2.tree contains "C$"
ip.src == 10.0.1.50
```

## Findings

| Time | Source | Destination | Share | Action |
|------|--------|-------------|-------|--------|
| 11:00 | 10.0.1.50 | 10.0.1.100 | \\10.0.1.100\IPC$ | Connect |
| 11:01 | 10.0.1.50 | 10.0.1.100 | \\10.0.1.100\C$ | File write |
| 11:05 | 10.0.1.50 | 10.0.1.101 | \\10.0.1.101\ADMIN$ | Connect |

## Analysis

1. Single source IP (10.0.1.50) accessed admin shares on 3 internal hosts
2. File written to C$ share — likely tool/payload staging
3. Correlates with Sysmon Event ID 3 (port 445) and Event 4624 Logon Type 3

## IOCs

```
Source: 10.0.1.50 (patient zero)
Targets: 10.0.1.100, 10.0.1.101
Ports: 445/TCP
```

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| SMB/Windows Admin Shares | T1021.002 |

Correlate with Splunk hunt: [hunt-06-lateral-movement.spl](../Threat-Hunting/hunts/hunt-06-lateral-movement.spl)
