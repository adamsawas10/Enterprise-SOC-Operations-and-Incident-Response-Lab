# Enterprise SOC Operations and Incident Response Lab

**Project type:** Defensive security training lab | **Data:** Synthetic | **Scope:** Offline Python correlation and analyst review | **Status:** Working demonstration, not a production SOC

## Overview

This repository demonstrates a Tier 1 SOC workflow using fictional activity for **Northstar Financial Services**. A Python correlator reads small, timestamped CSV datasets, identifies suspicious patterns, and produces structured alerts with evidence references and suggested next steps. The alerts are then assessed separately in an [evidence-based case review](analyst_case_reviews.md).

The key distinction is intentional: **a detection is not proof of malicious intent or compromise.** The program assigns `REVIEW_REQUIRED` rather than automatically closing or confirming an incident. The analyst review explains what the supplied evidence supports, what remains uncertain, the potential business risk, and what additional investigation would be justified.

> **Scope and provenance:** The version of this repository reviewed on October 29, 2026 contains **14 synthetic input records**: 11 Windows events, one endpoint event, one network event, and one approved-activity record. It generates **four triage candidates**. This repository alone does **not** contain a 618-event Windows export, a live Splunk deployment, the full phishing dataset, DNS telemetry, vulnerability scans, or proof of production containment. Those broader skills and scenarios must be supported by separately published artifacts before being claimed as demonstrated here.

## Results at a glance

| Measure | Demonstrated result |
|---|---|
| Input records | 14 synthetic records across four CSV files |
| Generated triage candidates | 4 |
| Automated output | `correlated_alerts.json` and `triage_report.md` |
| Unit tests | 9 passed in GitHub Codespaces on October 29, 2026 (user-verified terminal run) |
| Analyst assessments | [Four evidence-based case assessments](analyst_case_reviews.md), with uncertainty preserved |
| Production scope | None; fictional company, reserved documentation IP ranges, no real customer data |

## Detection-to-investigation workflow

```text
Synthetic Windows / endpoint / network / approved-change CSVs
                      |
                      v
              soc_correlator.py
                      |
             +--------+--------+
             |                 |
             v                 v
     correlated_alerts.json  triage_report.md
             |                 |
             +--------+--------+
                      |
                      v
           analyst_case_reviews.md
          (evidence, verdict, risk,
         limitations, recommended action)
```

### Detection scenarios

| Alert | Detection | Automated priority | Candidate MITRE ATT&CK mapping | Analyst assessment |
|---|---|---|---|---|
| AUTO-001 | Nine failed authentications for one account/source IP in eight minutes | MEDIUM | T1110 — Brute Force | Pattern confirmed; intent and compromise not established |
| AUTO-002 | Privileged-group membership event (Windows 4728) | MEDIUM | T1098 — Account Manipulation | Authorization and actor context unavailable |
| AUTO-003 | Hidden/encoded PowerShell and nearby network telemetry on same host | HIGH | T1059.001 — PowerShell | Suspicious, but network traffic cannot be attributed to the process |
| AUTO-004 | Windows audit-log clear with matching synthetic change metadata | LOW | T1070.001 — Clear Windows Event Logs | Potentially authorized; approval not independently confirmed |

Technique mappings are **investigation hypotheses**, not proof that adversary activity occurred.

## Repository contents

- [`soc_correlator.py`](soc_correlator.py): CSV parser and offline cross-source detection logic. Correlates authentication failures by account and source IP; identifies suspicious PowerShell command flags and nearby host network events; checks privileged-group changes and log-clearing activity against a synthetic approval window.
- [`test_soc_correlator.py`](test_soc_correlator.py): Unit tests for time parsing, authentication bursts, false matches, attribution limitations, and approved-activity handling.
- [`windows.csv`](windows.csv): Nine failed sign-ins plus one privileged-group change and one audit-log clear.
- [`endpoint.csv`](endpoint.csv), [`network.csv`](network.csv): A PowerShell process event and a separate host network event.
- [`approved_activities.csv`](approved_activities.csv): One simulated change-window record.
- [`correlated_alerts.json`](correlated_alerts.json): Structured, machine-generated triage candidates.
- [`triage_report.md`](triage_report.md): Human-readable, machine-generated alert evidence. Its **Pending analyst review** status is intentionally retained.
- [`analyst_case_reviews.md`](analyst_case_reviews.md): A separate, evidence-limited interpretation and response analysis of the four alerts.
- [`VALIDATION.md`](VALIDATION.md): Exact reproduction commands, expected results, and limitations.
- [`.github/workflows/soc-validation.yml`](.github/workflows/soc-validation.yml): Read-only GitHub Actions check of the nine tests and four expected alert candidates (runs after upload).
- [`.gitignore`](.gitignore): Ignores Python caches and local environment files.

## Reproduce the lab

Requires Python 3.10+ and the Python standard library; the offline correlator does not require Splunk or live cloud credentials.

```bash
python3 -m unittest -v test_soc_correlator.py

python3 soc_correlator.py \
  --windows windows.csv \
  --endpoint endpoint.csv \
  --network network.csv \
  --approved approved_activities.csv \
  --output /tmp/soc-recheck

cat /tmp/soc-recheck/triage_report.md
```

**Expected current sample result:** `Loaded 14 input records. Generated 4 triage candidates.` The sample should yield `Ran 9 tests` and `OK` when the tests pass. See [VALIDATION.md](VALIDATION.md) for what those checks do—and do not—verify.

## Analyst decision discipline

For each generated candidate, the assessment records:

1. **Observed evidence:** specific timestamps, event IDs, hosts, identities and cited input rows.
2. **Interpretation and limitations:** what is proven by the supplied data versus what would require more telemetry.
3. **Disposition:** confirmed rule match, potentially benign, or inconclusive—not an automatic conclusion of compromise.
4. **Business risk:** the conditional impact if the activity were part of an attack.
5. **Next steps:** verification, authorized containment *if warranted*, remediation, and evidence preservation.

A HIGH automated priority is a **triage priority**, not proof that an incident is malicious. No isolation, firewall blocking, role revocation, or vulnerability remediation is implemented or claimed in this repository.

## Separate related work

These repositories provide additional context and should be evaluated separately; their evidence is not part of the 14-record dataset above:

- [Splunk SIEM Home Lab](https://github.com/adamsawas10/splunk-siem-home-lab) — Windows event-log parsing and SIEM detection exercises.
- [Phishing Email Analysis Lab](https://github.com/adamsawas10/phishing-email-analysis-lab) — phishing and header-analysis exercises.
- [Multi-Cloud SOC & Incident Response](https://github.com/adamsawas10/multi-cloud-soc-incident-response) — separately documented AWS detection-to-incident-storage validation and read-only Azure RBAC monitoring work.

## Limitations and next improvements

- The dataset is intentionally small and synthetic; it does not demonstrate detection accuracy, throughput, or robustness on production telemetry.
- `endpoint.csv` and `network.csv` share a host and close timestamps but no PID/process GUID, so a causal PowerShell-to-network link is **not** established.
- A matching synthetic approved-activity record does not independently verify that a real change ticket was valid.
- The sample lacks authentication details such as logon type, successful follow-on activity, account ownership, and source context needed for stronger verdicts.
- There is no integration with a real ticketing system or proof of completed operational containment.
- Future improvements: add richer *synthetic* evidence, negative test scenarios, explicit end-to-end CI, and published artifacts for any broader lab claims.

## Portfolio integrity

All entities and IP addresses in this repository are fictional or reserved for documentation. Case reviews are educational evidence assessments, **not** real employer incidents or customer investigations. Scripts generate candidate alerts and intentionally require independent analyst judgment. The included assessments do not claim that unknown facts were verified or that response actions were executed.
