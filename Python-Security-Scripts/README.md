# Python Security Automation Scripts

Automated security log analysis using Python to identify failed logins, suspicious IPs, and file hashes.

## Scripts

| Script | Description | Usage |
|--------|-------------|-------|
| [ioc_checker.py](ioc_checker.py) | Scan files for IOC matches | `python ioc_checker.py -f log.txt` |
| [log_parser.py](log_parser.py) | Parse Windows security logs | `python log_parser.py security.log -s` |
| [failed_login_detector.py](failed_login_detector.py) | Detect brute-force patterns | `python failed_login_detector.py auth.log -t 5` |
| [hash_calculator.py](hash_calculator.py) | MD5/SHA1/SHA256 file hashing | `python hash_calculator.py sample.exe` |
| [virustotal_lookup.py](virustotal_lookup.py) | VirusTotal API queries | `python virustotal_lookup.py --hash <sha256>` |
| [suspicious_ip_checker.py](suspicious_ip_checker.py) | IP threat intel check | `python suspicious_ip_checker.py 1.2.3.4` |

## Setup

```bash
cd SOC-Projects/Python-Security-Scripts

# No external dependencies required for most scripts (stdlib only)
# For VirusTotal API:
set VT_API_KEY=your_api_key_here   # Windows
export VT_API_KEY=your_api_key_here  # Linux/Mac
```

## Quick Start Examples

### Parse security logs
```bash
python log_parser.py data/sample_security.log --summary
python log_parser.py data/sample_security.log --event 4625
```

### Detect brute force
```bash
python failed_login_detector.py data/sample_auth.log --threshold 5
```

### Calculate file hashes
```bash
python hash_calculator.py suspicious_file.exe
```

### Check IOCs
```bash
python ioc_checker.py --file data/sample_auth.log
python ioc_checker.py --indicator 185.220.101.45
```

### VirusTotal lookup
```bash
python virustotal_lookup.py --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
python virustotal_lookup.py --ip 8.8.8.8
python virustotal_lookup.py --domain example.com
```

### Suspicious IP check
```bash
python suspicious_ip_checker.py --file data/sample_auth.log --extract
```

## Sample Data

Sanitized sample logs in `data/`:
- [sample_auth.log](data/sample_auth.log) — Failed/successful login events
- [sample_security.log](data/sample_security.log) — Mixed security events
- [iocs.txt](data/iocs.txt) — Sample IOC list

## Resume Bullet

> Automated security log analysis using Python to identify failed logins, suspicious IPs, and file hashes.

## Related Projects

- [Splunk Detection Lab](../Splunk-Detection-Lab/) — SPL equivalents of Python detections
- [Malware Analysis](../Malware-Analysis/) — Use `hash_calculator.py` for sample hashing
