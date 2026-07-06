# Incident Response Portfolio

Conducted end-to-end incident response investigations documenting attack timelines, IOCs, root cause analysis, and remediation recommendations.

## Objectives

- Investigate multi-stage attacks from initial access to impact
- Build detailed incident timelines with evidence
- Extract and document IOCs for containment
- Provide root cause analysis and remediation recommendations
- Follow NIST incident response phases

## Skills Demonstrated

- Incident triage and scoping
- Timeline reconstruction
- Evidence collection and correlation
- IOC creation and sharing
- Containment and recovery planning
- Post-incident reporting

## NIST IR Phases Covered

```
1. Preparation     → Runbooks, tooling, lab environment
2. Detection       → Splunk alerts, user report
3. Analysis        → Timeline, scope, root cause
4. Containment     → Block IOCs, isolate host
5. Eradication     → Remove malware, disable accounts
6. Recovery        → Restore systems, monitor
7. Lessons Learned → Report and recommendations
```

## Case Studies

| Case | Scenario | Severity | Report |
|------|----------|----------|--------|
| IR-2025-001 | Phishing → PowerShell → Persistence → C2 | Critical | [ir-001-phishing-to-compromise.md](case-studies/ir-001-phishing-to-compromise.md) |

## Incident Report Template

Use [incident-report-template.md](incident-report-template.md) for new investigations.

## Resume Bullet

> Conducted end-to-end incident response investigations, documenting attack timelines, indicators of compromise, root cause analysis, and remediation recommendations.

## Related Projects

- [Phishing Investigation](../Phishing-Investigation/) — Initial access vector analysis
- [Splunk Detection Lab](../Splunk-Detection-Lab/) — Detections that triggered IR
- [Threat Hunting](../Threat-Hunting/) — Proactive discovery
- [SOC Home Lab](../SOC-Home-Lab/) — Lab environment for simulation
