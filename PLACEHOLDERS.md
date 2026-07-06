# Portfolio Placeholder Checklist

Track what still needs real lab work, evidence, or your data. Check items off as you complete them.

**Legend:** `[ ]` = not started · `[~]` = in progress · `[x]` = done

---

## Priority 1 — Must Replace (obvious placeholders)

### SOC Home Lab (`SOC-Home-Lab/`)

- [ ] Build Windows 11 VM with Sysmon installed
- [ ] Install Splunk Enterprise + Universal Forwarder
- [ ] Forward Security + Sysmon logs to Splunk
- [ ] Set up Kali Linux for Atomic Red Team simulations
- [ ] Replace example IPs/hostnames (`192.168.1.x`, `WIN11-VM`) with your actual lab values in `README.md`
- [ ] Fill **Findings** table in `README.md` — replace `YYYY-MM-DD` with real test dates
- [ ] Add Splunk dashboard screenshot → `screenshots/`
- [ ] Add Sysmon event screenshot → `screenshots/`
- [ ] Add log ingestion / forwarder confirmation screenshot → `screenshots/`

### Malware Analysis (`Malware-Analysis/`)

- [ ] Download a safe sample from [MalwareBazaar](https://bazaar.abuse.ch/) (static analysis only, isolated VM)
- [ ] Replace placeholder hashes in `reports/report-01-emotet-dropper.md`
  - [ ] Remove note: *"Hashes above are placeholders"*
  - [ ] Replace `[your-sample-sha256-here]` with real SHA256
  - [ ] Replace `d41d8cd9…` / `e3b0c442…` empty-file hashes
- [ ] Replace fictional domains (`malicious-c2.example.com`) with real IOCs from your sample
- [ ] Add PEStudio / VirusTotal screenshot → `screenshots/`
- [ ] Complete `reports/report-02-powershell-downloader.md` with a real `.ps1` sample OR mark as example-only

### Phishing Investigation (`Phishing-Investigation/`)

Redo **at least 2–3** case studies with real public samples (analyze headers/URLs safely — never click live links):

| Case | File | Replace |
|------|------|---------|
| [ ] | `case-studies/case-01-invoice-phish.md` | Fictional domains, IPs, dates |
| [ ] | `case-studies/case-02-ceo-fraud.md` | `attacker123@gmail.com`, scenario details |
| [ ] | `case-studies/case-03-malware-attachment.md` | Hash `a1b2c3d4…`, `evil-cdn.com` |
| [ ] | `case-studies/case-04-qr-phishing.md` | `microsoft-verify.secure-login.io` |
| [ ] | `case-studies/case-05-shipping-scam.md` | `fedex-delivery-track.com` |

**Safe sample sources:** [PhishTank](https://www.phishtank.com/) · [OpenPhish](https://openphish.com/)

- [ ] Add email header / VirusTotal screenshot for at least one case → `screenshots/`

### Incident Response (`Incident-Response/`)

- [ ] Run full attack chain in home lab (phishing sim → PowerShell → persistence → C2)
- [ ] Update `case-studies/ir-001-phishing-to-compromise.md` with real timeline from your lab
- [ ] Replace fictional hostnames (`FINANCE-PC-01`, `evil_admin`) with your VM details
- [ ] Replace hash `a1b2c3d4…` with real sample hash from your simulation
- [ ] Fill a new report from `incident-report-template.md` for a second IR case (optional)

### Python Security Scripts (`Python-Security-Scripts/`)

- [ ] Export real logs from Windows VM after Atomic Red Team tests
- [ ] Add real log file(s) to `data/` (keep sanitized — no real usernames/passwords)
- [ ] Update `data/iocs.txt` with IOCs from your investigations
- [ ] Run and verify each script against real exported logs:
  - [ ] `log_parser.py`
  - [ ] `failed_login_detector.py`
  - [ ] `ioc_checker.py`
  - [ ] `hash_calculator.py`
  - [ ] `suspicious_ip_checker.py`
  - [ ] `virustotal_lookup.py` (requires `VT_API_KEY`)

---

## Priority 2 — Screenshots to Add

| Project | Screenshot | Target path |
|---------|------------|-------------|
| [ ] | Splunk SOC dashboard | `SOC-Home-Lab/screenshots/` |
| [ ] | Splunk detection alert firing | `Splunk-Detection-Lab/screenshots/dashboard-overview.png` |
| [ ] | Wireshark DNS tunneling | `Network-Forensics/screenshots/dns-tunneling.png` |
| [ ] | Wireshark HTTP C2 beacon | `Network-Forensics/screenshots/http-c2-beacon.png` |
| [ ] | Nessus Windows scan results | `Vulnerability-Assessment/screenshots/nessus-windows.png` |
| [ ] | Nmap Linux scan results | `Vulnerability-Assessment/screenshots/nmap-linux.png` |
| [ ] | PEStudio / VirusTotal | `Malware-Analysis/screenshots/` |
| [ ] | Phishing header analysis | `Phishing-Investigation/screenshots/` |

> Create `screenshots/` folders in each project as needed. Only `SOC-Home-Lab/screenshots/` exists today.

---

## Priority 3 — Lab-Tested (written but not proven)

### Splunk Detection Lab (`Splunk-Detection-Lab/`)

Deploy and test detections in your Splunk instance:

| # | Detection | File | Deployed | Alert fires |
|---|-----------|------|----------|-------------|
| [ ] | Failed Logins | `detections/01_failed_logins.spl` | | |
| [ ] | Brute Force | `detections/02_brute_force.spl` | | |
| [ ] | PowerShell Execution | `detections/03_powershell_execution.spl` | | |
| [ ] | Encoded PowerShell | `detections/04_encoded_powershell.spl` | | |
| [ ] | New Admin Account | `detections/05_new_admin_account.spl` | | |
| [ ] | USB Insertion | `detections/06_usb_insertion.spl` | | |
| [ ] | RDP Login | `detections/07_rdp_login.spl` | | |
| [ ] | Suspicious Process | `detections/08_suspicious_process.spl` | | |
| [ ] | LSASS Access | `detections/09_lsass_access.spl` | | |
| [ ] | Service Install | `detections/10_service_install.spl` | | |
| [ ] | Registry Run Key | `detections/11_registry_run_key.spl` | | |
| [ ] | WMI Execution | `detections/12_wmi_execution.spl` | | |
| [ ] | Lateral Movement SMB | `detections/13_lateral_movement_smb.spl` | | |
| [ ] | After-Hours Login | `detections/14_after_hours_login.spl` | | |
| [ ] | Disabled Account Login | `detections/15_disabled_account_login.spl` | | |

- [ ] Build dashboard from `dashboards/dashboard-spec.md`
- [ ] Document false positives and tuning notes in `README.md`

### Threat Hunting (`Threat-Hunting/`)

| Hunt | File | Run on lab data | Report filed |
|------|------|-----------------|--------------|
| [ ] | Encoded PowerShell | `hunts/hunt-01-encoded-powershell.spl` | |
| [ ] | New Local Admin | `hunts/hunt-02-new-local-admin.spl` | |
| [ ] | WMI Execution | `hunts/hunt-03-wmi-execution.spl` | |
| [ ] | RDP Activity | `hunts/hunt-04-rdp-activity.spl` | |
| [ ] | Credential Dumping | `hunts/hunt-05-credential-dumping.spl` | |
| [ ] | Lateral Movement | `hunts/hunt-06-lateral-movement.spl` | |

- [ ] Replace fictional example in `README.md` (`WIN10-01`, `jsmith`) with your lab results
- [ ] Complete at least one filled report from `hunt-report-template.md`

### Network Forensics (`Network-Forensics/`)

- [ ] Download a PCAP from [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [ ] Update `analysis/dns-tunneling-analysis.md` with your PCAP findings
- [ ] Update `analysis/http-c2-analysis.md` with your PCAP findings
- [ ] Update `analysis/smb-lateral-movement.md` — ideally tied to your lab lateral movement sim
- [ ] Replace example IPs (`10.0.1.50`, `203.0.113.x`) with values from your capture

### Vulnerability Assessment (`Vulnerability-Assessment/`)

- [ ] Run Nmap against Windows VM — update `reports/va-report-windows.md`
- [ ] Run Nessus Essentials against Windows VM — update findings and CVEs
- [ ] Run Nmap/OpenVAS against Linux/Splunk VM — update `reports/va-report-linux.md`
- [ ] Replace lab IPs (`192.168.1.10`, `192.168.1.100`) with your network
- [ ] Add real CVSS scores from your scan output

---

## Priority 4 — Templates (keep as-is, fill copies)

These files are **intentional templates**. Do not delete — create new filled files when you complete real work:

| Template | Create new file when |
|----------|---------------------|
| `Incident-Response/incident-report-template.md` | Each new IR case → e.g. `case-studies/ir-002-*.md` |
| `Threat-Hunting/hunt-report-template.md` | Each completed hunt → e.g. `hunts/reports/hunt-001-*.md` |

Template blanks to fill in copies: `[Your Name]`, `YYYY-MM-DD`, `[Brief title]`, `[Name]`

---

## Priority 5 — Profile & Repo Cleanup

- [ ] Add `github.com/manusmart2/soc-analyst-labs` to resume
- [ ] Add portfolio link to LinkedIn
- [ ] Pin `soc-analyst-labs` on GitHub profile
- [ ] Change profile README status from "Documented" → "Lab tested" once evidence is added
- [ ] Remove duplicate `SOC-Projects/` folder from profile repo (`manusmart2/manusmart2`) when lab work is complete

---

## Suggested Weekly Plan

| Week | Focus | Check off |
|------|-------|-----------|
| 1 | SOC Home Lab setup + screenshots | Priority 1 → SOC Home Lab |
| 2 | Deploy 5 Splunk detections + 1 hunt | Priority 3 → Splunk + Threat Hunting |
| 3 | 2 phishing cases + 1 malware report | Priority 1 → Phishing + Malware |
| 4 | Full IR timeline + 1 PCAP + 1 VA scan | Priority 1 → IR · Priority 3 → Network + VA |

---

## Interview-Ready Checkpoint

You're ready when you can honestly say:

- [ ] Home lab runs with real logs in Splunk
- [ ] At least 5 detections fired on real attack simulations
- [ ] At least 2 phishing investigations use real sample analysis
- [ ] At least 1 full IR case has real timeline + screenshots
- [ ] Python scripts run on exported lab logs
- [ ] Portfolio has screenshots in at least 4 projects

---

## Quick Reference — Spot a Placeholder

| If you see… | Action |
|-------------|--------|
| `YYYY-MM-DD` | Replace with real date |
| `[your-…-here]` | Replace with your data |
| `a1b2c3d4…` / empty file hashes | Use real hashes from your analysis |
| `evil-`, `malicious-`, `attacker123` | Fictional — replace with real IOCs |
| `Add screenshot to…` | Add the image file |
| `sample_*.log` | Add real exported logs alongside or instead |
| `✅ Documented` on profile | Upgrade to lab-tested with proof |

---

*Last updated: 2026-03-09 · Update this file as you complete items and commit progress to the repo.*
