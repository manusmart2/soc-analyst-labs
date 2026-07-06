# HTTP C2 Beacon Analysis

## Hypothesis

Malware communicating with command-and-control server via periodic HTTP POST requests.

## Wireshark Filters

```
http.request.method == "POST"
http.host contains "evil"
http.time > 60
```

## Findings

| Indicator | Value |
|-----------|-------|
| Source IP | 10.0.1.50 |
| Destination | 185.220.101.45:443 |
| HTTP Host | update.evil-cdn.com |
| Pattern | POST every 60 seconds |
| User-Agent | Mozilla/4.0 (inconsistent with modern browser) |
| Payload size | Consistent 256 bytes (encrypted beacon) |

## Timeline

| Time | Method | URI | Size |
|------|--------|-----|------|
| 10:00:00 | POST | /gate.php | 256 |
| 10:01:00 | POST | /gate.php | 256 |
| 10:02:00 | POST | /gate.php | 256 |

## IOCs

```
update.evil-cdn.com
185.220.101.45
/gate.php
```

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Application Layer Protocol: Web Protocols | T1071.001 |

Add screenshot to `screenshots/http-c2-beacon.png`
