# Splunk Dashboard Specification

## Dashboard: SOC Operations Overview

### Panel 1: Failed Login Trend (24h)
```spl
index=wineventlog EventCode=4625
| timechart span=1h count BY host
```

### Panel 2: Top Failed Login Accounts
```spl
index=wineventlog EventCode=4625 earliest=-24h
| top limit=10 Account_Name
```

### Panel 3: PowerShell Executions
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe" earliest=-24h
| stats count BY host, User
| sort -count
```

### Panel 4: New Accounts Created (7d)
```spl
index=wineventlog EventCode=4720 earliest=-7d
| table _time, host, TargetUserName, SubjectUserName
```

### Panel 5: RDP Logins
```spl
index=wineventlog EventCode=4624 Logon_Type=10 earliest=-24h
| stats count BY src_ip, Account_Name, host
```

### Panel 6: Critical Alerts Queue
```spl
index=wineventlog OR index=sysmon
| search severity="critical" OR severity="high"
| stats latest(_time) AS last_seen, count BY detection_name, host, severity
| sort -severity, -count
```

## Build Instructions

1. Dashboards → Create New Dashboard → "SOC Operations Overview"
2. Add panels using queries above
3. Set time range default to "Last 24 hours"
4. Export dashboard XML for version control (optional)
5. Add screenshot to `../screenshots/dashboard-overview.png`
