# Case Study 01: Invoice-Themed Phishing

## Summary

| Field | Value |
|-------|-------|
| **Case ID** | PHISH-2025-001 |
| **Date Reported** | 2025-03-15 |
| **Reporter** | Finance team |
| **Classification** | Credential Harvesting |
| **Severity** | High |
| **Status** | Closed — IOCs blocked |

## Email Details

| Field | Value |
|-------|-------|
| Claimed Sender | accounts@legit-vendor.com |
| Actual Return-Path | bounce@malicious-invoice.net |
| Subject | URGENT: Overdue Invoice #INV-2025-4892 |
| Recipient | finance@company.local |

## Header Analysis

```
From: "Accounts Payable" <accounts@legit-vendor.com>
Reply-To: payments@malicious-invoice.net
Return-Path: <bounce@malicious-invoice.net>
Authentication-Results: spf=fail; dkim=none; dmarc=fail
X-Originating-IP: 185.220.101.45
```

### Findings

1. **SPF Fail** — Sending IP `185.220.101.45` not authorized for `legit-vendor.com`
2. **DKIM None** — No DKIM signature present
3. **DMARC Fail** — Domain alignment failed
4. **Reply-To mismatch** — Reply-To points to `malicious-invoice.net` (registered 3 days ago)
5. **Display name spoof** — "Accounts Payable" impersonates known vendor

## URL Analysis

| URL (defanged) | VirusTotal | URLScan |
|----------------|------------|---------|
| `hxxps://legit-vendor[.]secure-pay-invoice[.]com/login` | 12/90 malicious | Phishing login page clone |

### Domain WHOIS

- **Domain:** secure-pay-invoice.com
- **Registered:** 2025-03-12 (3 days before email)
- **Registrar:** Privacy-protected
- **Nameservers:** Bulletproof hosting provider

## IP Reputation

| IP | AbuseIPDB Score | Country | Reports |
|----|-----------------|---------|---------|
| 185.220.101.45 | 89% | NL | 47 abuse reports |

## Indicators of Compromise

```
# Domains
malicious-invoice.net
secure-pay-invoice.com

# IPs
185.220.101.45

# URLs
hxxps://legit-vendor.secure-pay-invoice.com/login

# Email addresses
payments@malicious-invoice.net
bounce@malicious-invoice.net
```

## Containment Actions

- [x] Block domains at web proxy/firewall
- [x] Block sender IP at perimeter
- [x] Submit URLs to VirusTotal community
- [x] Notify finance team — no credentials entered
- [x] Search mail logs for other recipients

## Recommendations

1. Enable DMARC enforcement (`p=reject`) for company domain
2. Add external email banner for messages from outside organization
3. Conduct phishing awareness refresher for finance team

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Phishing | T1566.002 | Spearphishing Link |
| Valid Accounts | T1078 | Credential harvesting via fake login |
