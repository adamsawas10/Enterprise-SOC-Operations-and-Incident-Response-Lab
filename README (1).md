# Enterprise SOC Operations and Incident Response Home Lab

## Overview

This project simulates the daily work of a Tier 1 Security Operations Center analyst for a fictional company called **Northstar Financial Services**.

The lab uses synthetic Windows, endpoint, email, network, DNS, and vulnerability data. The data is reviewed in Splunk to detect suspicious activity, investigate alerts, assign severity, document findings, and decide whether each case should be escalated or closed.

All organizations, users, IP addresses, events, alerts, tickets, and vulnerabilities in this project are fictional or created for training purposes. No production, employer, customer, or personal data is included.

## Project Goals

The project demonstrates the ability to:

- Monitor and investigate SIEM alerts
- Analyze Windows Security and Sysmon events
- Investigate phishing emails and extract indicators of compromise
- Review suspicious PowerShell activity
- Investigate privileged account changes
- Distinguish true positives from benign activity
- Prioritize and track vulnerabilities
- Map supported activity to MITRE ATT&CK
- Create incident reports, tickets, runbooks, and escalation notes
- Use Python to support basic SOC analysis

## SOC Workflow

Each investigation follows the same analyst process:

1. Ingest synthetic telemetry into Splunk.
2. Run a detection search.
3. Review the generated alert.
4. Collect and correlate supporting evidence.
5. Determine whether the activity is malicious, benign, or inconclusive.
6. Assign a severity level.
7. Escalate, contain, remediate, or close the case.
8. Document the investigation and update SOC metrics.

## Lab Environment

### NS-DC01 — Domain Controller

Windows Server system providing Active Directory, DNS, authentication, user accounts, security groups, and Group Policy.

### NS-WKS01 — Finance Workstation

Windows 11 workstation used by a standard finance employee. It produces Windows Security, Sysmon, PowerShell, process, and network telemetry.

### NS-WKS02 — Administrative Workstation

Windows 11 workstation used by the fictional IT administrator. It supports privileged-access and administrative-activity investigations.

### NS-LNX01 — Linux Server

Ubuntu server representing an internal business application. It is used for network monitoring and vulnerability-management scenarios.

### NS-MAIL01 — Mail Telemetry Source

Synthetic email-security source containing legitimate, suspicious, and malicious email events.

### NS-SIEM01 — SIEM Server

Splunk Enterprise server used for log ingestion, detection searches, dashboards, investigations, and reporting.

### NS-TEST01 — Authorized Test System

Isolated system used to generate safe and controlled activity for detection testing inside the lab.

## Data Sources

### Windows Security Events

The dataset contains 618 synthetic records, including normal logins, failed logins, repeated authentication-failure bursts, account changes, privileged-group changes, and one audit-log-clearing event.

### Sysmon and PowerShell Events

The endpoint dataset contains normal and suspicious process activity, parent-child process relationships, PowerShell execution, file activity, and outbound network connections.

### Email Security Events

The email dataset contains one legitimate message and two simulated phishing messages. The fields include sender details, reply-to values, SPF, DKIM, DMARC, URLs, domains, and attachments.

### Network and DNS Events

The network and DNS datasets contain normal traffic, authorized reconnaissance, suspicious outbound communication, and scenario-related domain lookups.

### Vulnerability Findings

The vulnerability dataset contains initial findings, severity ratings, affected assets, remediation recommendations, ownership, and verification results.

## Detection Rules

The lab contains detection logic for:

- Repeated failed authentication attempts
- Suspicious phishing indicators
- Hidden or encoded PowerShell execution
- Privileged account and group changes
- Windows audit-log clearing

Each detection includes the purpose of the rule, required fields, investigation guidance, expected false positives, and MITRE ATT&CK mapping where supported.

## Completed Investigations

### INC-001 — Repeated Authentication Failures

Nine failed login attempts targeted the fictional user `jdoe` from the reserved test IP address `192.0.2.44`. No successful login followed the failures.

The activity was classified as a Medium-severity unsuccessful brute-force true positive. The case includes an investigation timeline, supporting evidence, severity reasoning, escalation criteria, and remediation recommendations.

### INC-002 — Phishing Email

A credential-themed message failed SPF and DMARC checks, used mismatched sender and reply-to domains, and directed the recipient to a non-corporate test domain.

The email was classified as a High-severity phishing true positive. The case includes header analysis, IOC extraction, verdict reasoning, containment recommendations, and a phishing-triage playbook.

### INC-003 — Suspicious PowerShell Activity

A hidden encoded PowerShell process launched from `cmd.exe`, connected to the reserved test address `203.0.113.50` over port 443, and created additional file activity.

The activity was classified as suspicious and escalated for endpoint review. The case includes process analysis, command-line review, network evidence, MITRE ATT&CK mapping, and containment recommendations.

### INC-004 — Privileged Account Change

A sequence of privileged-group and temporary-account changes occurred without an approved fictional change record.

The activity was classified as unauthorized and escalated. The temporary account was removed, privileged access was reviewed, and remediation actions were documented.

### INC-005 — Benign Administrative Activity

A Windows audit-log-clearing alert was traced to an approved fictional maintenance activity performed by the IT administrator.

The alert was closed as a benign positive. The investigation documents the evidence supporting closure and recommends contextual tuning without disabling the detection.

### VULN-001 — Vulnerability Remediation Cycle

A simulated High-severity outdated web package was identified on the Linux server. The finding was prioritized, assigned to an owner, remediated, and verified as closed through a follow-up scan.

A separate Medium-severity SMB-signing finding remained open with a documented remediation owner and target date.

## Playbooks and Runbooks

The project includes analyst procedures for:

- Authentication alert investigation
- Phishing email triage
- Suspicious PowerShell investigation
- Privileged identity-change investigation
- Vulnerability remediation and verification

These documents define the evidence an analyst should collect, how severity should be assigned, when escalation is required, and what information should be included in the final case record.

## Case Management

Each investigation contains:

- Alert information
- Affected assets and users
- Evidence collected
- Investigation timeline
- Analyst reasoning
- True-positive, benign-positive, or inconclusive verdict
- Severity classification
- MITRE ATT&CK mapping where supported
- Escalation decision
- Containment and remediation recommendations
- Final case status
- Lessons learned

The project also includes a fictional alert queue, case register, severity matrix, escalation matrix, and shift-handoff report.

## Automation

Two Python utilities support the lab:

- A Windows log analyzer that summarizes authentication failures
- An email parser that extracts and scores suspicious email indicators

The scripts are intended to support analyst review rather than replace manual investigation and judgment.

## SOC Metrics

The fictional reporting period includes:

- Six completed cases
- Five confirmed security or vulnerability findings
- One benign positive
- Four escalations
- Median security-case triage time of seven minutes
- Median security-case closure time of 28 minutes

These numbers describe the synthetic lab cases only and do not represent production SOC performance.

## Skills Demonstrated

- Splunk Enterprise
- SPL searches
- SIEM alert triage
- Windows Security Event analysis
- Sysmon analysis
- PowerShell investigation
- Phishing analysis
- IOC extraction
- Active Directory monitoring
- Vulnerability management
- MITRE ATT&CK fundamentals
- Incident documentation
- Escalation decisions
- Detection tuning
- Python automation

## Portfolio Statement

This project is a simulated enterprise SOC home lab built with synthetic telemetry. It demonstrates hands-on practice with alert detection, investigation, documentation, escalation, and remediation workflows.

It should not be presented as professional SOC employment, production monitoring, or real customer incident experience.

## Resume Description

Built and operated a simulated enterprise SOC home lab using Splunk and synthetic Windows, Sysmon, email, network, DNS, and vulnerability telemetry. Developed detection searches, investigated security alerts, documented true-positive and benign-positive decisions, mapped supported activity to MITRE ATT&CK, created analyst runbooks, and tracked a vulnerability through remediation and verification.
