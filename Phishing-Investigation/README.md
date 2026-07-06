# Phishing Email Investigation

Performed phishing investigations by analyzing email headers, authentication records, URLs, and malware indicators.

## Objectives

- Analyze email headers for spoofing and routing anomalies
- Validate SPF, DKIM, and DMARC authentication
- Investigate URLs and domains using threat intelligence
- Document findings in structured incident reports
- Build a repeatable investigation workflow

## Skills Demonstrated

- Email header analysis
- SPF / DKIM / DMARC validation
- URL and domain investigation
- Threat intelligence (VirusTotal, AbuseIPDB, Hybrid Analysis)
- Incident report writing

## Tools

| Tool | Purpose |
|------|---------|
| MXToolbox | SPF/DKIM/DMARC lookup |
| VirusTotal | URL, domain, hash reputation |
| AbuseIPDB | IP reputation and abuse reports |
| Hybrid Analysis | Sandbox malware analysis |
| URLScan.io | URL screenshot and redirect chain |
| WHOIS | Domain registration lookup |

## Investigation Workflow

```
1. Receive report / sample
       ↓
2. Extract headers (From, Reply-To, Return-Path, Received)
       ↓
3. Check SPF / DKIM / DMARC
       ↓
4. Analyze URLs (defang, expand, check reputation)
       ↓
5. Check attachments (hash → VirusTotal)
       ↓
6. Document IOCs and write incident report
       ↓
7. Recommend containment (block sender, URL, hash)
```

## Case Studies

| # | Case | Type | Key Finding | Report |
|---|------|------|-------------|--------|
| 1 | Invoice-themed phishing | Credential harvest | SPF fail, lookalike domain | [case-01-invoice-phish.md](case-studies/case-01-invoice-phish.md) |
| 2 | CEO fraud / BEC | Business email compromise | Display name spoof, DMARC none | [case-02-ceo-fraud.md](case-studies/case-02-ceo-fraud.md) |
| 3 | Malware attachment | Dropper (.docm) | Macro-enabled, VT 45/70 | [case-03-malware-attachment.md](case-studies/case-03-malware-attachment.md) |
| 4 | QR code phishing | Quishing | URL in image, newly registered domain | [case-04-qr-phishing.md](case-studies/case-04-qr-phishing.md) |
| 5 | Shipping notification | Credential harvest | Typosquat domain, valid DKIM from wrong sender | [case-05-shipping-scam.md](case-studies/case-05-shipping-scam.md) |

## Header Analysis Checklist

- [ ] **From** vs **Return-Path** — Do they match?
- [ ] **Reply-To** — Different from sender?
- [ ] **Received** chain — Unexpected hops or geographic anomalies?
- [ ] **Authentication-Results** — SPF, DKIM, DMARC pass/fail?
- [ ] **X-Originating-IP** — Known malicious IP?
- [ ] **Message-ID** — Valid format for claimed domain?

## SPF / DKIM / DMARC Quick Reference

| Result | Meaning | Action |
|--------|---------|--------|
| SPF Pass | Sending IP authorized | Continue investigation |
| SPF Fail | IP not authorized | High suspicion |
| DKIM Pass | Message integrity verified | Good sign, but check domain |
| DKIM Fail | Signature invalid | Likely spoofed or modified |
| DMARC Pass | Alignment confirmed | Lower spoofing risk |
| DMARC Fail | Alignment failed | Likely phishing |

## Safe Sample Sources

Use public phishing corpora for practice (never click live links):

- [PhishTank](https://www.phishtank.com/)
- [OpenPhish](https://openphish.com/)
- [APWG eCrime Exchange](https://ecrimerx.net/)

## Resume Bullet

> Performed phishing investigations by analyzing email headers, URLs, domains, and malware indicators using VirusTotal, AbuseIPDB, and Hybrid Analysis.

## Related Projects

- [Incident Response](../Incident-Response/) — Full attack chain from phishing email
- [Malware Analysis](../Malware-Analysis/) — Static analysis of email attachments
