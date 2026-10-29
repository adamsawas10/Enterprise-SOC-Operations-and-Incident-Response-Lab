# Reproducibility and Validation

## Scope

This guide reproduces the **offline, standard-library Python** SOC correlation demonstration using the four committed synthetic CSV datasets. It does not require AWS, Azure, Splunk, or customer logs.

## Preconditions

- Python 3.10 or newer.
- Run commands from the repository root containing `soc_correlator.py`, `test_soc_correlator.py`, and the four CSV files.
- Keep `test_soc_correlator.py` configured with `ROOT = Path(__file__).resolve().parent` and `DATA = ROOT` so tests find the committed CSVs.

## 1. Run the unit tests

```bash
python3 -m unittest -v test_soc_correlator.py
```

**Verified by user Codespaces screenshot, October 29, 2026:**

```text
Ran 9 tests in 0.037s

OK
```

The tests cover timestamp validation, authentication-burst detection, failed-then-successful logons, cross-user separation, host-level correlation caveats, approval-window treatment, and false-match prevention. They validate the included test cases, **not** broad detection accuracy in production environments.

## 2. Regenerate reports without overwriting committed artifacts

```bash
python3 soc_correlator.py \
  --windows windows.csv \
  --endpoint endpoint.csv \
  --network network.csv \
  --approved approved_activities.csv \
  --output /tmp/soc-recheck
```

**Verified by user Codespaces screenshot, October 29, 2026:**

```text
Loaded 14 input records. Generated 4 triage candidates.
Reports: /tmp/soc-recheck/correlated_alerts.json and /tmp/soc-recheck/triage_report.md
```

## 3. Inspect output

```bash
cat /tmp/soc-recheck/triage_report.md
```

The report should contain `AUTO-001` through `AUTO-004`. Each generated alert remains a **pending analyst review** candidate. Do not replace these machine-produced states with human verdicts inside the generator. Human interpretation belongs in [`analyst_case_reviews.md`](analyst_case_reviews.md).

## Inputs used

| File | Data rows | Purpose |
|---|---:|---|
| `windows.csv` | 11 | Authentication failures, group change, audit-log clear |
| `endpoint.csv` | 1 | Suspicious PowerShell flags |
| `network.csv` | 1 | Same-host network activity near PowerShell event |
| `approved_activities.csv` | 1 | Synthetic audit-log clearing approval context |
| **Total** | **14** | **Four alert candidates** |

## Evidence limitations

- A successful test run proves that this particular code processes these sample inputs as expected; it does **not** verify a claimed 618-record dataset or prove live Splunk operation.
- The correlator deliberately refuses to infer intent, process ownership, or independently validated approval when those facts are absent.
- The event and IP data are synthetic; the source and destination IPs fall in documentation-reserved ranges.
- The case reviews recommend actions but **do not** claim they were executed.

## Continuous validation after publication

`.github/workflows/soc-validation.yml` is included in this update. On a push to `main` or pull request, GitHub Actions will run the unit tests, regenerate the triage output, and verify four candidates retain `REVIEW_REQUIRED`. **The workflow has not yet run in your repository**; inspect its first check result after uploading.
