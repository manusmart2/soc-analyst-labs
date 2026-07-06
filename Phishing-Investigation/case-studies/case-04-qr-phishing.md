# Case Study 04: QR Code Phishing (Quishing)

## Summary

| Field | Value |
|-------|-------|
| **Case ID** | PHISH-2025-004 |
| **Classification** | Quishing (QR Phishing) |
| **Severity** | Medium |

## Description

Email appeared to be from Microsoft 365 with a QR code image prompting users to "scan to verify account." QR code encoded URL bypassing text-based URL filters.

## Analysis

1. Extracted QR code URL using image analysis tool
2. URL: `hxxps://microsoft-verify[.]secure-login[.]io/auth`
3. Domain registered 24 hours prior
4. VirusTotal: 8/90 malicious
5. URLScan shows Microsoft login clone

## IOCs

```
microsoft-verify.secure-login.io
```

## Recommendations

- Train users on QR code phishing
- Consider stripping external images in email or warning on QR-containing emails

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Phishing | T1566.002 |
