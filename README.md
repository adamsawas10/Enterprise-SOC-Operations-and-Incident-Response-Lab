Enterprise SOC Operations and Incident Response Lab

Executive Summary

This project simulates Tier 1 Security Operations Center work for the fictional organization Northstar Financial Services. The lab is designed to demonstrate alert monitoring, SIEM investigation, phishing analysis, identity monitoring, vulnerability management, MITRE ATT&CK mapping, escalation decisions, documentation, and basic analyst automation.

The project builds on prior hands-on work with Splunk, Windows Security logs, phishing analysis, Active Directory, Ubuntu Linux, Nmap, and Python. Evidence-specific values such as timestamps, IP addresses, usernames, screenshots, alert counts, and final verdicts must be replaced with results collected from the actual lab.

## Environment

### NS-DC01 — Domain Controller

* **Purpose:** Provides centralized identity management, authentication, DNS, user accounts, security groups, and Group Policy.
* **Operating System:** Windows Server
* **Primary Data Sources:** Windows Security Event Logs, Active Directory events, authentication logs, and group membership changes.
* **Security Use:** Supports investigations involving failed logins, account creation, account lockouts, privileged access, and administrative changes.

### NS-WKS01 — Employee Workstation

* **Purpose:** Represents a standard employee device used for daily business activity.
* **Operating System:** Windows 11
* **Primary Data Sources:** Windows Security Event Logs, Sysmon telemetry, PowerShell logs, process activity, and network connections.
* **Assigned User:** `jdoe`
* **Security Use:** Supports investigations involving phishing, suspicious PowerShell activity, failed authentication, and endpoint behavior.

### NS-WKS02 — Administrative Workstation

* **Purpose:** Represents a workstation used by IT personnel for administrative tasks.
* **Operating System:** Windows 11
* **Primary Data Sources:** Windows Security Event Logs, Sysmon telemetry, administrative logins, PowerShell activity, and privileged account actions.
* **Assigned User:** `itadmin`
* **Security Use:** Supports investigations involving privileged access, administrative changes, and false-positive validation.

### NS-LNX01 — Linux Application Server

* **Purpose:** Represents a Linux server hosting internal services or applications.
* **Operating System:** Ubuntu Linux
* **Primary Data Sources:** Authentication logs, system logs, service logs, network activity, and vulnerability scan results.
* **Security Use:** Supports investigations involving network reconnaissance, repeated login attempts, exposed services, and vulnerable software.

### NS-SIEM01 — SIEM Server

* **Purpose:** Centralizes security logs for monitoring, detection, investigation, dashboard creation, and reporting.
* **Platform:** Splunk Enterprise
* **Primary Data Sources:** Windows Security logs, Sysmon logs, Active Directory events, Linux logs, and test activity.
* **Security Use:** Supports alert creation, SPL searches, event correlation, investigation timelines, dashboards, and incident documentation.

### NS-TEST01 — Isolated Security Testing System

* **Purpose:** Generates authorized and controlled activity for detection testing.
* **Operating System:** Ubuntu Linux or an isolated security-testing virtual machine.
* **Primary Tools:** Nmap, SMBclient, test scripts, and other safe administrative utilities.
* **Security Use:** Supports approved simulations involving network reconnaissance, repeated authentication failures, and detection validation.
* **Restriction:** This system must only interact with devices inside the isolated lab environment.

## Planned Investigations

### INC-001 — Repeated Authentication Failures

* **Scenario:** Multiple failed authentication attempts are detected against an employee account.
* **Primary Data Sources:** Windows Security Event IDs 4625 and 4624.
* **Tools:** Splunk Enterprise, Windows Event Viewer, and SPL.
* **Primary Skills:** Alert validation, authentication analysis, timeline creation, severity classification, and escalation.
* **MITRE ATT&CK Mapping:** T1110 — Brute Force
* **Investigation Goal:** Determine whether the activity represents malicious brute-force behavior, an incorrectly configured service, or a user entering an incorrect password.
* **Expected Deliverables:** SPL detection query, incident report, evidence screenshots, severity decision, escalation decision, and authentication-alert runbook.

### INC-002 — Phishing Email Investigation

* **Scenario:** An employee reports a suspicious email that may contain sender spoofing, a malicious URL, or a credential-harvesting attempt.
* **Primary Data Sources:** Email headers, sender information, URLs, domains, IP addresses, and attachment details.
* **Tools:** PhishTool, ANY.RUN, Python, and approved reputation sources.
* **Primary Skills:** Email-header analysis, IOC extraction, URL investigation, verdict determination, and incident documentation.
* **Investigation Goal:** Determine whether the message is malicious, suspicious, spam, or legitimate.
* **Expected Deliverables:** Phishing incident report, extracted IOC list, email-header analysis, screenshots, recommended containment actions, and phishing-triage playbook.

### INC-003 — Suspicious PowerShell Activity

* **Scenario:** A PowerShell process generates activity that may indicate unauthorized script execution.
* **Primary Data Sources:** PowerShell logs, Sysmon events, process creation events, command-line arguments, user information, and network activity.
* **Tools:** Splunk Enterprise, Sysmon, Windows Event Viewer, and SPL.
* **Primary Skills:** Process analysis, command-line review, endpoint investigation, MITRE ATT&CK mapping, and escalation.
* **Investigation Goal:** Determine whether the PowerShell activity is malicious, authorized administrative activity, or a false positive.
* **Expected Deliverables:** SPL detection query, process timeline, incident report, evidence screenshots, severity decision, and escalation recommendation.

### INC-004 — Privileged Account Change

* **Scenario:** A user is added to a privileged Active Directory security group.
* **Primary Data Sources:** Active Directory events, Windows Security Event Logs, administrator activity, and change timestamps.
* **Tools:** Windows Server, Active Directory, Splunk Enterprise, and Windows Event Viewer.
* **Primary Skills:** Identity monitoring, privileged-access analysis, authorization validation, and incident escalation.
* **Investigation Goal:** Determine who made the change, which account received additional privileges, whether the action was authorized, and what risk was introduced.
* **Expected Deliverables:** Privileged-change detection query, incident timeline, evidence screenshots, authorization decision, severity classification, and remediation recommendation.

### INC-005 — Benign Administrative Activity

* **Scenario:** An authorized administrative action triggers a security detection.
* **Primary Data Sources:** Windows Security Event Logs, Sysmon events, administrative records, and related change documentation.
* **Tools:** Splunk Enterprise, Windows Event Viewer, and Active Directory.
* **Primary Skills:** False-positive validation, contextual analysis, detection tuning, and case closure.
* **Investigation Goal:** Demonstrate why the activity is legitimate and determine whether the detection rule should be adjusted.
* **Expected Deliverables:** False-positive incident report, supporting evidence, closure justification, documented tuning recommendation, and updated detection logic where appropriate.

### VULN-001 — Vulnerability Assessment and Remediation

* **Scenario:** A vulnerability scan identifies security weaknesses on a lab system.
* **Primary Data Sources:** Vulnerability scanner output, CVE information, CVSS scores, affected software versions, asset criticality, and rescan results.
* **Tools:** Nessus Essentials or Greenbone/OpenVAS.
* **Primary Skills:** Vulnerability analysis, risk prioritization, remediation tracking, verification scanning, and technical reporting.
* **Investigation Goal:** Identify genuine vulnerabilities, prioritize them based on technical severity and asset impact, apply safe remediation, and verify that the weaknesses were resolved.
* **Expected Deliverables:** Initial vulnerability scan, prioritized findings table, remediation plan, evidence of completed fixes, verification scan, closure status, and vulnerability-remediation procedure.


Portfolio Rules:

Do not publish real credentials, personal data, API keys, private IP details that expose a real environment, or unredacted email samples.

Do not claim an incident was malicious unless the evidence supports that conclusion.

Do not report simulated activity as a real-world attack.

Replace every TODO field with observed evidence before presenting the case as complete.

Keep screenshots readable and explain why each one matters.

Resume-Ready Project Description

Use only after the corresponding work is completed and verified:

Built and operated a virtual enterprise SOC environment centralizing Windows, Active Directory, Linux, email, and vulnerability telemetry for alert monitoring and Tier 1 investigation. Developed and tested SIEM detections, investigated simulated security cases, mapped supported activity to MITRE ATT&CK, documented escalation and containment recommendations, and tracked vulnerability remediation through verification scans.
