# Northstar SOC — Evidence-Based Analyst Case Reviews

**Environment:** Fictional Northstar Financial Services training lab  
**Inputs:** 14 committed synthetic CSV records  
**Source:** [`correlated_alerts.json`](correlated_alerts.json) and [`triage_report.md`](triage_report.md)  
**Purpose:** Evaluate the four automated alert candidates, separate observed facts from hypotheses, and communicate risk and recommended action.

> **Important:** This is an educational desk assessment of synthetic evidence, not a record of real-world investigation or completed containment. The automated outputs correctly retain `REVIEW_REQUIRED`. The conclusions below concern the *available sample*, not any unseen telemetry. No genuine ticket, account-owner interview, EDR investigation, or host isolation is represented as performed.

## Analyst assessment summary

| Candidate | What the rule detected | Evidence-based assessment | Priority | Final incident determination |
|---|---|---|---|---|
| AUTO-001 | Authentication failure burst | Rule-match **true positive**; potentially suspicious | MEDIUM | Malicious intent / compromise **unconfirmed** |
| AUTO-002 | Privileged group change | Event observed; change authorization unknown | MEDIUM | **Inconclusive; requires authorized-change validation** |
| AUTO-003 | Hidden/encoded PowerShell with close-in-time network event | Suspicious process flags and nearby network event observed | HIGH | **Inconclusive; process-to-network attribution unproven** |
| AUTO-004 | Log clear with matching synthetic approval metadata | Context supports a possible benign explanation | LOW | **Potentially benign; approval not independently verified** |

**Terminology:** A *rule-match true positive* means the pattern was accurately detected. It does **not** mean a malicious attack was confirmed. Automated *priority* directs review order and does not establish impact.

---

## AUTO-001 — Repeated authentication failures

**Related scenario:** INC-001 from the original lab description  
**Candidate mapping:** MITRE ATT&CK T1110 — Brute Force  
**Automated priority:** MEDIUM  
**Assessment:** Detection true positive; intent and compromise undetermined

### Observed evidence

- `windows.csv` records `windows:2` through `windows:10` contain **nine** Windows `4625` failed-authentication events.
- All nine reference host `NS-DC01`, account `jdoe`, and source `192.0.2.44`.
- The events span **2026-10-01 09:00 to 09:08 UTC**, an eight-minute interval between the first and last timestamps.
- No `4624` successful authentication for that account/source appears in the **supplied** Windows sample.
- `192.0.2.44` belongs to a documentation-only address range; this is synthetic telemetry, not a real attacker attribution.

### Analysis and verdict

The repeated failures satisfy the lab's burst-detection rule. Password guessing is a plausible hypothesis, but nine failed logins alone do not establish an external attacker, account compromise, or user intent. There is no account-owner context, logon type, approved-test metadata for these attempts, or follow-on telemetry. The defensible conclusion is a **confirmed pattern detection with an inconclusive security determination**.

### Potential business impact

If such activity targeted a real enterprise identity, it could create account-lockout disruption or indicate attempts to gain unauthorized access. **Neither outcome is established in this sample.**

### Recommended investigation and response

1. Check account-owner activity and whether the events coincide with an authorized password test or mistyped credentials.
2. Correlate with additional `4624` successes, logon types, MFA and identity-provider events, source context, and endpoint telemetry.
3. Preserve relevant records and escalate if suspicious context or follow-on access is identified.
4. Consider account protection, MFA review, or a narrowly scoped source restriction **only if validated and authorized**; no control changes were performed in this lab.

**Evidence references:** [`windows.csv`](windows.csv) rows 2–10; [`correlated_alerts.json`](correlated_alerts.json) `AUTO-001`.

---

## AUTO-002 — Privileged-group membership change

**Related scenario:** INC-004 in the original lab description (not fully independently evidenced here)  
**Candidate mapping:** MITRE ATT&CK T1098 — Account Manipulation  
**Automated priority:** MEDIUM  
**Assessment:** Change observed; authorization unknown

### Observed evidence

- `windows.csv` record `windows:11` is Windows Event ID `4728` on `NS-DC01` at **2026-10-02 10:00 UTC**.
- Its `username` column contains `temp_admin`, but the abbreviated CSV does **not** expose separate actor, added member, group SID, or target-group identity fields.
- The single committed approved-activities row concerns Event ID `1102` on a different date, **not** this group-change event.

### Analysis and verdict

A privileged-group-related event warrants identity governance review. The sample does not establish who initiated the change, which group was affected, whether it was approved, or whether it represented malicious persistence. **An absent approval in this tiny CSV is not proof of an unauthorized change.** The correct verdict is **inconclusive pending change-record and identity verification**.

### Potential business impact

If an unauthorized account received privileged access, it could increase the likelihood of data exposure, lateral movement, or tampering with security controls. This is a **conditional risk**, not an observed loss.

### Recommended investigation and response

1. Obtain the full event fields and identify actor, member, affected group, and security identifiers.
2. Correlate with service desk/change records, IAM policy, and related group membership events.
3. Check subsequent privileged sign-ins and administrative actions.
4. If unauthorized access is confirmed, follow approved procedures to revoke inappropriate membership, protect credentials, assess scope, and preserve evidence. **No access was revoked as part of this repository.**

**Evidence references:** [`windows.csv`](windows.csv) row 11; [`approved_activities.csv`](approved_activities.csv); [`correlated_alerts.json`](correlated_alerts.json) `AUTO-002`.

---

## AUTO-003 — Hidden/encoded PowerShell and network context

**Related scenario:** INC-003 from the original lab description  
**Candidate mapping:** MITRE ATT&CK T1059.001 — PowerShell  
**Automated priority:** HIGH  
**Assessment:** Suspicious execution characteristics; attribution incomplete

### Observed evidence

- `endpoint.csv` (`endpoint:2`) records PowerShell launched on `NS-WKS01` by `jdoe` at **2026-10-02 11:00 UTC**.
- The command line contains `-WindowStyle Hidden -EncodedCommand [REDACTED_SYNTHETIC]`.
- `network.csv` (`network:2`) records a connection from **the same host** to reserved test IP `203.0.113.50`, port `443`, at **11:01 UTC**.
- The two samples do **not** contain a shared PID, process GUID, socket owner, decoded command, file hash, or command execution result.

### Analysis and verdict

Hidden-window and encoded PowerShell flags are worth investigating but can also appear in legitimate administration. The host/time proximity makes the network event relevant **context**, not proof that this PowerShell process created the connection. The redacted synthetic command cannot be decoded. The defensible finding is **suspicious behavior requiring more endpoint evidence**, not confirmed command-and-control or exfiltration.

### Potential business impact

If malicious, unauthorized script execution could affect workstation integrity, credentials, or business data. The available synthetic records show **no verified theft, execution payload outcome, or lateral movement**.

### Recommended investigation and response

1. Obtain full PowerShell script block and process-creation telemetry, parent process, command content and signer information.
2. Join process and connection evidence by PID or process GUID rather than host/time alone.
3. Verify approved administrative activity and look for persistence, downloads, credential access or suspicious child processes.
4. Escalate for endpoint review; isolate the device **only on corroborating evidence and with appropriate authorization**. No isolation occurred here.

**Evidence references:** [`endpoint.csv`](endpoint.csv) row 2; [`network.csv`](network.csv) row 2; [`correlated_alerts.json`](correlated_alerts.json) `AUTO-003`.

---

## AUTO-004 — Windows Security log cleared with change-window context

**Related scenario:** INC-005 from the original lab description  
**Candidate mapping:** MITRE ATT&CK T1070.001 — Clear Windows Event Logs  
**Automated priority:** LOW  
**Assessment:** Potentially authorized maintenance; confirmation unavailable

### Observed evidence

- `windows.csv` (`windows:12`) records Event ID `1102`, host `NS-DC01`, `username=admin`, at **2026-10-03 03:00 UTC**.
- `approved_activities.csv` (`approved:2`) provides synthetic change reference `CHG-DEMO-001`, matching the same host and event, with a window from **02:30 to 03:30 UTC**.
- The CSV supports **a matching claimed approval window**, but does not contain an actual, independently validated change request or a reviewer confirmation.

### Analysis and verdict

The matching fictional change metadata offers a plausible benign reason for a log-clear event. It is **not** proof of approved execution. An Event ID `1102` still merits confirmation because clearing audit logs can reduce visibility. Classification: **potential benign positive, pending validation of authorization and purpose**. Do not claim the activity was definitively closed as legitimate solely because the synthetic record matched.

### Potential business impact

Audit-log clearing may reduce investigative coverage and potentially affect retention or compliance obligations if unexpected. The sample does not establish unauthorized deletion or a policy violation.

### Recommended investigation and response

1. Validate the ticket `CHG-DEMO-001` against the approved change system and authorized administrator.
2. Confirm maintenance scope, timing and expected log handling; check for other suspicious changes.
3. Preserve alternate logs and verify retention/forwarding controls.
4. If authorization is confirmed, document a benign disposition and consider detection tuning that **adds context rather than disabling the alert**. No real ticket validation or log restoration occurred here.

**Evidence references:** [`windows.csv`](windows.csv) row 12; [`approved_activities.csv`](approved_activities.csv) row 2; [`correlated_alerts.json`](correlated_alerts.json) `AUTO-004`.

---

## What is—and is not—demonstrated

**Demonstrated by committed artifacts:** reproducible offline detection, timestamp-aware correlation, four generated triage candidates, evidence reference trails, conservative automated classifications, and reasoned educational case assessments.

**Not demonstrated by these artifacts:** confirmed malicious intent, business compromise, a validated enterprise change ticket, proof of PowerShell-to-network process ownership, real-time Splunk alerting, operational remediation, physical host isolation, full phishing investigations, or vulnerability-closure evidence.

## Interview-ready explanation

> I built an offline SOC correlation lab using synthetic Windows, endpoint, network and change-window records. It generates structured alert candidates, but it doesn't label an attack as confirmed just because a rule fires. I then document the evidence, confidence limits, potential business risk and next investigative steps. For example, I found a nine-attempt authentication burst, but I explicitly distinguished that verified pattern from an unproven account compromise.

This explanation accurately reflects the published evidence without implying production SOC experience.
