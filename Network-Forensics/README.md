# Network Traffic Analysis / Forensics

Investigated network traffic using Wireshark to identify malicious DNS, HTTP, SMB activity and document attack indicators.

## Objectives

- Analyze PCAP files for suspicious network behavior
- Identify C2 communication, data exfiltration, and lateral movement
- Document network-based IOCs
- Build Wireshark display filter reference for SOC use

## Skills Demonstrated

- Wireshark packet analysis
- Protocol analysis (DNS, HTTP, SMB, FTP, ICMP)
- Network IOC extraction
- Traffic pattern identification

## Tools

| Tool | Purpose |
|------|---------|
| Wireshark | GUI packet analysis |
| tshark | CLI packet analysis |
| tcpdump | Packet capture |
| Zeek | Network security monitoring |
| NetworkMiner | Artifact extraction from PCAPs |

## Analysis Scenarios

| # | Scenario | Protocol | Key Indicator | Doc |
|---|----------|----------|---------------|-----|
| 1 | DNS tunneling | DNS | Long subdomain queries, high entropy | [dns-tunneling-analysis.md](analysis/dns-tunneling-analysis.md) |
| 2 | HTTP C2 beacon | HTTP | Periodic POST to suspicious domain | [http-c2-analysis.md](analysis/http-c2-analysis.md) |
| 3 | SMB lateral movement | SMB | Admin share access across hosts | [smb-lateral-movement.md](analysis/smb-lateral-movement.md) |

## Wireshark Display Filters

```
# DNS queries to suspicious domains
dns.qry.name contains "malicious"

# HTTP POST requests (potential C2)
http.request.method == "POST"

# SMB file access
smb2.cmd == 5

# Large ICMP packets (potential tunneling)
icmp and frame.len > 100

# Traffic to/from specific IP
ip.addr == 185.220.101.45

# Unencrypted credentials (FTP)
ftp.request.command == "PASS"
```

## tshark CLI Examples

```bash
# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Top talkers by IP
tshark -r capture.pcap -q -z conv,ip

# HTTP hosts
tshark -r capture.pcap -Y http -T fields -e http.host | sort | uniq -c | sort -rn
```

## Safe PCAP Sources

- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [PCAP files on GitHub](https://github.com/activecm/rita-legacy/tree/master/RitaExamplePCAPs)

## Resume Bullet

> Investigated network traffic using Wireshark to identify malicious DNS, HTTP, and SMB activity and document attack indicators.

## Related Projects

- [Incident Response](../Incident-Response/) — Network evidence in IR timeline
- [Threat Hunting](../Threat-Hunting/) — Hunt for lateral movement (SMB)
