# Hunt Report Template

## Hunt Information

| Field | Value |
|-------|-------|
| **Hunt ID** | HUNT-YYYY-### |
| **Hunt Name** | [Name] |
| **Analyst** | [Your Name] |
| **Date** | YYYY-MM-DD |
| **MITRE ATT&CK** | [Technique ID] — [Name] |
| **Status** | Open / Closed / Escalated |

## Hypothesis

> [Describe the attacker behavior you are searching for and why]

## Data Sources

- [ ] Windows Security Logs
- [ ] Sysmon
- [ ] Network/Firewall Logs
- [ ] Proxy Logs
- [ ] Other: ___

## Time Range

`earliest=-30d latest=now`

## Hunt Query

```spl
[paste SPL here]
```

## Results Summary

| Total Events | True Positives | False Positives | Benign True Positives |
|-------------|----------------|-----------------|----------------------|
| | | | |

## Notable Findings

### Finding 1
- **Host:** 
- **User:** 
- **Timestamp:** 
- **Details:** 
- **Verdict:** True Positive / False Positive / BTP

## IOCs Discovered

```
[list any new IOCs]
```

## Recommendations

1. [ ] Create detection rule
2. [ ] Escalate to IR
3. [ ] Block IOCs
4. [ ] No action — benign activity

## Follow-Up

- Detection created: [link to .spl file]
- IR case opened: [case ID]
