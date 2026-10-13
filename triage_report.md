# Northstar SOC - Automated Correlation / Triage Report

**Training environment only.** The correlations below are leads for analyst investigation, not final verdicts.

Alerts: **4**

## AUTO-001 - repeated_failed_authentication (MEDIUM)

Multiple authentication failures occurred for the same account and source IP; this does not establish attacker intent.

**Supporting CSV evidence:**

- `windows:2` | 2026-10-01T09:00:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:3` | 2026-10-01T09:01:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:4` | 2026-10-01T09:02:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:5` | 2026-10-01T09:03:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:6` | 2026-10-01T09:04:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:7` | 2026-10-01T09:05:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:8` | 2026-10-01T09:06:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:9` | 2026-10-01T09:07:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44
- `windows:10` | 2026-10-01T09:08:00+00:00 | event_id=4625, host=NS-DC01, username=jdoe, source_ip=192.0.2.44

**Analyst follow-up:**

- Check logon type, IP origin, and account-owner context.
- Review related host events and approved activities.
- Document analyst verdict and escalate if evidence warrants it.

**Candidate MITRE ATT&CK mapping:** T1110 (Brute Force)

**Verdict:** Pending analyst review.

## AUTO-002 - privileged_group_change (MEDIUM)

Privileged-group membership changed.

**Supporting CSV evidence:**

- `windows:11` | 2026-10-02T10:00:00+00:00 | event_id=4728, host=NS-DC01, username=temp_admin

**Analyst follow-up:**

- Check the approved change record and identity of the actor.
- Confirm exact event details and surrounding activity.
- Record a justified benign, malicious, or inconclusive verdict.

**Candidate MITRE ATT&CK mapping:** T1098 (Account Manipulation)

**Verdict:** Pending analyst review.

## AUTO-003 - powershell_execution_with_network_context (HIGH)

PowerShell launched with encoded or hidden-window options. Nearby outbound network activity was observed from the same host, but process ownership is NOT established.

**Supporting CSV evidence:**

- `endpoint:2` | 2026-10-02T11:00:00+00:00 | host=NS-WKS01, username=jdoe, process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
- `network:2` | 2026-10-02T11:01:00+00:00 | host=NS-WKS01, destination_ip=203.0.113.50, destination_port=443

**Analyst follow-up:**

- Check full command and parent process in endpoint telemetry.
- Validate whether activity was sanctioned administration.
- Correlate process GUID/PID to network event before attributing traffic.

**Candidate MITRE ATT&CK mapping:** T1059.001 (PowerShell)

**Verdict:** Pending analyst review.

## AUTO-004 - audit_log_cleared (LOW)

A Windows Security audit log was cleared. Matching approved-activity metadata exists; verify the ticket before judging the activity benign.

**Supporting CSV evidence:**

- `windows:12` | 2026-10-03T03:00:00+00:00 | event_id=1102, host=NS-DC01, username=admin
- `approved:2` | 2026-10-03T03:00:00+00:00 | event_id=1102, host=NS-DC01, ticket=CHG-DEMO-001

**Analyst follow-up:**

- Check the approved change record and identity of the actor.
- Confirm exact event details and surrounding activity.
- Record a justified benign, malicious, or inconclusive verdict.

**Candidate MITRE ATT&CK mapping:** T1070.001 (Clear Windows Event Logs)

**Verdict:** Pending analyst review.

