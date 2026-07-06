# Case Study 02: CEO Fraud (Business Email Compromise)

## Summary

| Field | Value |
|-------|-------|
| **Case ID** | PHISH-2025-002 |
| **Classification** | Business Email Compromise (BEC) |
| **Severity** | Critical |
| **Status** | Closed — wire transfer prevented |

## Email Details

| Field | Value |
|-------|-------|
| Claimed Sender | ceo@company.local (display name only) |
| Actual From | external@gmail.com |
| Subject | Urgent wire transfer needed today |

## Header Analysis

```
From: "John Smith (CEO)" <attacker123@gmail.com>
Reply-To: attacker123@gmail.com
Authentication-Results: spf=pass (google.com); dkim=pass; dmarc=pass
```

### Findings

1. **Display name spoof** — Shows "John Smith (CEO)" but actual address is Gmail
2. **SPF/DKIM/DMARC pass** — For gmail.com, NOT company.local (legitimate Gmail account)
3. **No company domain** — Classic BEC using free email with executive display name
4. **Urgency language** — "Wire $45,000 today, do not call me I'm in meetings"

## Investigation Steps

1. Verified CEO was not traveling and did not send email
2. Checked SPF — passes for Gmail (attacker's real account)
3. Identified 3 other employees received similar emails
4. Blocked sender at mail gateway
5. Finance team confirmed no wire initiated

## IOCs

```
# Email
attacker123@gmail.com

# Subject pattern
Urgent wire transfer
```

## Recommendations

1. Implement display name warnings for external senders using internal executive names
2. Require dual approval for wire transfers over threshold
3. Out-of-band verification for financial requests

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Phishing | T1566.001 — Spearphishing Attachment / social engineering |
| Impersonation | Social engineering (BEC) |
