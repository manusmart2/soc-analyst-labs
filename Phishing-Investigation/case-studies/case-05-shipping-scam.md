# Case Study 05: Shipping Notification Scam

## Summary

| Field | Value |
|-------|-------|
| **Case ID** | PHISH-2025-005 |
| **Classification** | Credential Harvesting |
| **Severity** | Medium |

## Email Details

| Field | Value |
|-------|-------|
| Claimed Sender | noreply@fedex.com |
| Actual Domain | fedex-delivery-track.com (typosquat) |
| Subject | Package delivery failed — action required |

## Header Analysis

```
From: FedEx <noreply@fedex-delivery-track.com>
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
```

### Findings

1. **Typosquat domain** — `fedex-delivery-track.com` ≠ `fedex.com`
2. **Authentication passes** — For the typosquat domain (attacker owns it)
3. **Link** — Points to fake FedEx tracking page collecting payment info

## IOCs

```
fedex-delivery-track.com
hxxps://fedex-delivery-track.com/track?id=FAKE123
```

## Lesson

SPF/DKIM/DMARC can all pass when the attacker controls the sending domain. Always verify the actual domain matches the legitimate organization.

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Phishing | T1566.002 |
