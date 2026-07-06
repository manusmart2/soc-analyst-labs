# SOC Home Lab

**Highest priority project** — A full security operations lab for log collection, attack simulation, and incident investigation.

## Objectives

- Deploy a Windows 11 endpoint with Sysmon for enhanced telemetry
- Forward Windows Event Logs and Sysmon data to Splunk Enterprise
- Simulate attacks from Kali Linux using Atomic Red Team
- Investigate generated alerts and build detection dashboards
- Document end-to-end analyst workflows

## Skills Demonstrated

- Windows Event Logs
- Sysmon configuration and analysis
- Splunk log ingestion and search
- Attack simulation and detection
- Incident investigation

## Lab Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Windows 11 VM  │────▶│ Splunk Universal │────▶│ Splunk Enterprise│
│  + Sysmon       │     │ Forwarder        │     │ (Indexer/Search) │
│  + Win Event Log│     └──────────────────┘     └─────────────────┘
└────────┬────────┘                                      │
         │                                               ▼
         │                                      ┌─────────────────┐
┌────────▼────────┐                             │ Dashboards &    │
│  Kali Linux VM  │── Atomic Red Team attacks ─▶│ Detections      │
│  (Attacker)     │                             └─────────────────┘
└─────────────────┘
```

## Tools

| Tool | Purpose |
|------|---------|
| Windows 11 VM | Victim endpoint |
| Kali Linux | Attack simulation |
| Splunk Enterprise | SIEM / log analysis |
| Splunk Universal Forwarder | Log shipping |
| Sysmon | Enhanced endpoint telemetry |
| Atomic Red Team | MITRE-mapped attack simulation |

## Setup Guide

### 1. Install Splunk Enterprise

```bash
# Download from https://www.splunk.com/en_us/download/splunk-enterprise.html
# Default web UI: https://localhost:8000
```

### 2. Install Sysmon on Windows 11

Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

Use the SwiftOnSecurity configuration (recommended baseline):

```powershell
# Download sysmon config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

# Install Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Verify installation:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### 3. Install Splunk Universal Forwarder

1. Install Splunk UF on the Windows VM
2. Configure `inputs.conf` to collect:
   - `WinEventLog:Security`
   - `WinEventLog:System`
   - `WinEventLog:Application`
   - `Microsoft-Windows-Sysmon/Operational`

Example `inputs.conf`:

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
```

Example `outputs.conf` (point to your Splunk indexer):

```ini
[tcpout]
defaultGroup = splunk_indexers

[tcpout:splunk_indexers]
server = 192.168.1.100:9997
```

### 4. Configure Kali Linux (Attacker)

```bash
# Install Atomic Red Team
pwsh -c "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics"

# Example: simulate failed logins
Invoke-AtomicTest T1110.001 -TargetMachineName WIN11-VM
```

## Attack Scenarios to Simulate

| Atomic Test | MITRE Technique | Expected Detection |
|-------------|-----------------|-------------------|
| T1110.001 — Brute Force | T1110 | Multiple Event 4625 |
| T1059.001 — PowerShell | T1059.001 | Sysmon Event 1, 4688 |
| T1136.001 — Create Account | T1136.001 | Event 4720 |
| T1021.001 — RDP | T1021.001 | Event 4624 Logon Type 10 |
| T1547.001 — Registry Run Key | T1547.001 | Sysmon Event 13 |

## Investigation Workflow

1. **Alert triggers** in Splunk (see [Splunk Detection Lab](../Splunk-Detection-Lab/))
2. **Triage** — Identify affected host, user, timeframe
3. **Correlate** — Pivot across Security, Sysmon, and Network logs
4. **Scope** — Determine if isolated or lateral movement
5. **Document** — Timeline, IOCs, severity, recommendations

## Sample Investigation Query

```spl
index=wineventlog OR index=sysmon host="WIN11-VM"
| where _time >= relative_time(now(), "-1h")
| eval source_log=if(index="sysmon", "Sysmon", "Windows")
| table _time, source_log, EventCode, EventID, Account_Name, Image, CommandLine, DestinationIp
| sort _time
```

## Dashboards to Build

- Failed login attempts by host (last 24h)
- Sysmon process creation timeline
- New account creation alerts
- RDP authentication events
- Top noisy hosts / users

Add screenshots to `screenshots/` after building your lab.

## Findings (Template)

| Date | Attack Simulated | Detection Fired? | Investigation Notes |
|------|------------------|--------------------|-------------------|
| YYYY-MM-DD | T1110 Brute Force | Yes — 6+ failed logins | Correlated to Kali IP |
| YYYY-MM-DD | T1059 PowerShell | Yes — encoded command | Sysmon Event ID 1 |
| YYYY-MM-DD | T1136 New Admin | Yes — Event 4720 | Account: `evil_admin` |

## Resume Bullet

> Built a SOC home lab using Splunk Enterprise, Sysmon, Windows, and Kali Linux to collect endpoint logs, investigate security events, and create detection dashboards.

## Related Projects

- [Splunk Detection Lab](../Splunk-Detection-Lab/) — Detection rules for this lab
- [Threat Hunting](../Threat-Hunting/) — Proactive hunts on lab data
- [Incident Response](../Incident-Response/) — Full IR case study
