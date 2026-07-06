# DNS Tunneling Analysis

## PCAP Reference

Source: Malware Traffic Analysis (practice sample)

## Hypothesis

Attacker exfiltrating data or establishing C2 via DNS queries to avoid firewall detection.

## Analysis Steps

1. Open PCAP in Wireshark
2. Filter: `dns.flags.response == 0` (queries only)
3. Sort by length — tunneling uses long subdomain strings
4. Check query frequency — beaconing pattern

## Wireshark Filters

```
dns.qry.name.len > 50
dns.count > 100 && ip.src == 10.0.1.50
```

## Findings

| Indicator | Value |
|-----------|-------|
| Source IP | 10.0.1.50 (internal victim) |
| Query domain | `aGVsbG8gd29ybGQ.tunnel.evil-domain.com` |
| Query count | 847 queries in 30 minutes |
| Avg subdomain length | 63 characters (max DNS label) |
| Encoding | Base64 in subdomain labels |

## Network IOCs

```
# Domain
tunnel.evil-domain.com
evil-domain.com

# IP (DNS server queried)
203.0.113.10
```

## Detection Recommendations

- Alert on DNS queries with subdomain length > 50 characters
- Alert on > 100 DNS queries/minute from single host to same domain
- Block `evil-domain.com` at DNS sinkhole

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Exfiltration Over Alternative Protocol | T1048.003 |
| Application Layer Protocol: DNS | T1071.004 |

Add Wireshark screenshot to `screenshots/dns-tunneling.png`
