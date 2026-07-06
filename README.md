# SOC Analyst Labs

**Manohar CH** | Hands-on security operations projects for SOC Analyst roles

[![Splunk](https://img.shields.io/badge/Splunk-Detection%20Engineering-65A637?style=flat&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![Python](https://img.shields.io/badge/Python-Security%20Automation-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)](https://attack.mitre.org/)

A collection of practical SOC projects built while transitioning from **10+ years in QA** to **SOC Analyst**. Each project includes documentation, Splunk queries, Python scripts, MITRE ATT&CK mappings, and investigation templates.

**Profile:** [github.com/manusmart2](https://github.com/manusmart2)

📋 **[Placeholder checklist →](PLACEHOLDERS.md)** — Track lab work and evidence still needed

---

## Priority Projects (Start Here)

| # | Project | Description |
|---|---------|-------------|
| 1 | [SOC Home Lab](SOC-Home-Lab/) | Splunk + Sysmon + Windows/Kali attack simulation lab |
| 2 | [Splunk Detection Lab](Splunk-Detection-Lab/) | 15 detection rules with dashboards and MITRE mapping |
| 3 | [Phishing Investigation](Phishing-Investigation/) | 5 case studies with header/URL/malware analysis |
| 4 | [Python Security Scripts](Python-Security-Scripts/) | Automation for IOC checks, log parsing, VT lookups |
| 5 | [Incident Response](Incident-Response/) | End-to-end phishing-to-compromise case study |

## All Projects

| Project | Skills |
|---------|--------|
| [SOC Home Lab](SOC-Home-Lab/) | Splunk, Sysmon, Atomic Red Team, Windows logs |
| [Splunk Detection Engineering](Splunk-Detection-Lab/) | 15+ SPL rules, dashboards, MITRE mapping |
| [Phishing Investigations](Phishing-Investigation/) | Email headers, SPF/DKIM/DMARC, VirusTotal |
| [Python Security Automation](Python-Security-Scripts/) | IOC checker, log parser, VT API lookup |
| [Incident Response](Incident-Response/) | Timeline, IOCs, containment, recovery |
| [Threat Hunting](Threat-Hunting/) | Hypothesis-driven hunts in Splunk |
| [Malware Analysis (Static)](Malware-Analysis/) | PE analysis, hashes, IOC reports |
| [Network Forensics](Network-Forensics/) | Wireshark, DNS/HTTP/SMB analysis |
| [Vulnerability Assessment](Vulnerability-Assessment/) | Nmap, Nessus, CVSS prioritization |

---

## Repository Structure

```
soc-analyst-labs/
├── SOC-Home-Lab/
├── Splunk-Detection-Lab/
│   ├── detections/          # 15 SPL detection queries
│   └── dashboards/
├── Phishing-Investigation/
│   └── case-studies/
├── Python-Security-Scripts/
├── Incident-Response/
├── Threat-Hunting/
├── Malware-Analysis/
├── Network-Forensics/
└── Vulnerability-Assessment/
```

## Skills Demonstrated

- Windows Event Log analysis (4624, 4625, 4688, 7045)
- Sysmon endpoint telemetry (Event IDs 1, 3, 7, 10, 11)
- Splunk SPL detection engineering
- Phishing email forensics (SPF, DKIM, DMARC)
- Static malware analysis and IOC extraction
- Python security automation
- Incident response documentation
- Network traffic analysis
- Vulnerability assessment and risk prioritization

## Tools

`Splunk` `Sysmon` `Windows Event Logs` `Python` `MITRE ATT&CK` `Wireshark` `Nmap` `VirusTotal` `Atomic Red Team` `Kali Linux` `PowerShell` `PEStudio` `Nessus`

## Disclaimer

- Malware samples are analyzed **statically only** using safe repositories
- Never execute unknown malware on your host or production network
- All log data in this repo is **synthetic or sanitized**

## Contact

- **Email:** [manoharch99@gmail.com](mailto:manoharch99@gmail.com)
- **GitHub:** [@manusmart2](https://github.com/manusmart2)
