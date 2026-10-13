#!/usr/bin/env python3
"""Offline SOC cross-source correlation for a fictional Splunk training lab.

No live connections or automatic verdicts. Works only with explicitly supplied CSV files.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any

ALIASES = {
    'timestamp': ('timestamp', '_time', 'TimeCreated', 'time'),
    'event_id': ('event_id', 'EventCode', 'EventID', 'eventcode'),
    'host': ('host', 'ComputerName', 'Computer', 'computer_name', 'hostname'),
    'username': ('username', 'TargetUserName', 'user', 'Account_Name', 'AccountName'),
    'source_ip': ('source_ip', 'IpAddress', 'Source_Network_Address', 'src_ip', 'src'),
    'process': ('process', 'Image', 'NewProcessName', 'process_name', 'image'),
    'command_line': ('command_line', 'CommandLine', 'cmdline', 'process_command_line'),
    'destination_ip': ('destination_ip', 'dest_ip', 'DestinationIp', 'dest', 'dst_ip'),
    'destination_port': ('destination_port', 'dest_port', 'DestinationPort', 'dst_port'),
    'start': ('start', 'approved_start'),
    'end': ('end', 'approved_end'),
    'ticket': ('ticket', 'change_id', 'change_ticket'),
}

ALLOWED_WINDOWS_IDS = {'4624', '4625', '1102', '4728', '4732', '4756'}
GROUP_IDS = {'4728', '4732', '4756'}
PWSH_FLAGS = re.compile(r'(?i)(?:^|\s)(?:-|/)(?:enc(?:odedcommand)?|w(?:indowstyle)?\s+hidden)\b')


def parse_time(value: str) -> datetime:
    raw = value.strip()
    if not raw:
        raise ValueError('empty timestamp')
    try:
        if re.fullmatch(r'\d+(?:\.\d+)?', raw):
            result = datetime.fromtimestamp(float(raw), tz=timezone.utc)
        else:
            result = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except (ValueError, OverflowError) as exc:
        raise ValueError(f'invalid timestamp {raw!r}') from exc
    if result.tzinfo is None:
        raise ValueError(f'timestamp requires timezone/UTC offset: {raw!r}')
    return result.astimezone(timezone.utc)


def load_csv(path: Path | None, source: str, required: tuple[str, ...]) -> list[dict[str, Any]]:
    if path is None:
        return []
    with path.open(encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        if not columns:
            raise ValueError(f'{path}: CSV header is missing')
        mappings = {key: next((n for n in ALIASES[key] if n in columns), None) for key in ALIASES}
        missing = [key for key in required if not mappings[key]]
        if missing:
            raise ValueError(f'{path}: missing {", ".join(missing)}; detected columns: {", ".join(columns)}')
        records = []
        for n, record in enumerate(reader, 2):
            if not any(v and str(v).strip() for v in record.values()):
                continue
            row = {key: str(record.get(col) or '').strip() if col else '' for key, col in mappings.items()}
            try:
                row['when'] = parse_time(row['timestamp'])
                if row['start']:
                    row['start_at'] = parse_time(row['start'])
                if row['end']:
                    row['end_at'] = parse_time(row['end'])
            except ValueError as exc:
                raise ValueError(f'{path}:{n}: {exc}') from exc
            row['ref'] = f'{source}:{n}'
            row['source'] = source
            records.append(row)
    return sorted(records, key=lambda r: r['when'])


def evidence(row: dict[str, Any]) -> dict[str, str]:
    parts = ('event_id', 'host', 'username', 'source_ip', 'process', 'destination_ip', 'destination_port', 'ticket')
    return {'ref': row['ref'], 'source': row['source'], 'time': row['when'].isoformat(),
            **{k: row[k] for k in parts if row.get(k)}}


def make_alert(category: str, severity: str, description: str, matched: list[dict],
               recommendations: list[str], techniques: list[str] | None = None,
               details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {'id': '', 'category': category, 'triage_priority': severity,
            'analyst_verdict': 'REVIEW_REQUIRED', 'interpretation': description,
            'evidence': [evidence(r) for r in matched],
            'investigation_next_steps': recommendations,
            'attack_mapping_candidates': techniques or [], 'details': details or {}}


def detect_auth(windows: list[dict], threshold: int = 5, window_minutes: int = 10,
                success_minutes: int = 15) -> list[dict]:
    """Group failure bursts by source IP and account; optionally attach a success."""
    events_by_key: dict[tuple[str, str], list[dict]] = {}
    for event in windows:
        if event['event_id'] not in ('4624', '4625'):
            continue
        user, ip = event['username'], event['source_ip']
        if not user or user == '-' or not ip or ip == '-':
            continue  # Never correlate unrelated users with missing identifiers.
        events_by_key.setdefault((user.casefold(), ip), []).append(event)

    alerts = []
    window = timedelta(minutes=window_minutes)
    for (_, ip), events in events_by_key.items():
        events.sort(key=lambda x: x['when'])
        failures: list[dict] = []
        active_cluster: list[dict] = []
        def emit(cluster: list[dict], matched_success: dict | None):
            # A continuous trickle of attempts is not necessarily >=threshold
            # attempts in *one* window. Select the densest qualifying window.
            best: list[dict] = []
            for end in cluster:
                portion = [e for e in cluster if timedelta(0) <= end['when'] - e['when'] <= window]
                if len(portion) > len(best):
                    best = portion
            if len(best) < threshold:
                return
            if matched_success and not (timedelta(0) <= matched_success['when'] - cluster[-1]['when']
                                        <= timedelta(minutes=success_minutes)):
                matched_success = None
            source_ip, username = best[0]['source_ip'], best[0]['username']
            related = best + ([matched_success] if matched_success else [])
            alerts.append(make_alert(
                'success_after_failed_authentication' if matched_success else 'repeated_failed_authentication',
                'HIGH' if matched_success else 'MEDIUM',
                ('A successful authentication followed a burst of failures for the same account and source IP; '
                 'this does not confirm compromise.' if matched_success else
                 'Multiple authentication failures occurred for the same account and source IP; '
                 'this does not establish attacker intent.'), related,
                ['Check logon type, IP origin, and account-owner context.',
                 'Review related host events and approved activities.',
                 'Document analyst verdict and escalate if evidence warrants it.'], ['T1110 (Brute Force)'],
                {'username': username, 'source_ip': source_ip,
                 'failure_count': len(best), 'successful_authentication_observed': bool(matched_success)}))
        for event in events:
            if event['event_id'] == '4625':
                # Distinguish new bursts from previous clusters on a quiet interval.
                if active_cluster and event['when'] - active_cluster[-1]['when'] > window:
                    emit(active_cluster, None)
                    active_cluster = []
                active_cluster.append(event)
                failures = [e for e in active_cluster if event['when'] - e['when'] <= window]
            else:
                if active_cluster:
                    recent = [e for e in active_cluster if active_cluster[-1]['when'] - e['when'] <= window]
                    valid = timedelta(0) <= event['when'] - active_cluster[-1]['when'] <= timedelta(minutes=success_minutes)
                    emit(recent if valid else active_cluster, event if valid else None)
                    active_cluster = []
                    failures = []
        if active_cluster:
            # Deduplicate by treating each uninterrupted burst as one candidate.
            recent = [e for e in active_cluster if active_cluster[-1]['when'] - e['when'] <= window]
            emit(recent, None)
    return alerts


def detect_endpoint(endpoint: list[dict], network: list[dict], correlate_minutes: int = 5) -> list[dict]:
    alerts = []
    for process in endpoint:
        name = process['process'].replace('\\', '/').split('/')[-1].casefold()
        if name not in {'powershell.exe', 'pwsh.exe'}:
            continue
        if not PWSH_FLAGS.search(process['command_line']):
            continue
        host = process['host'].casefold()
        related = [row for row in network if host and row['host'].casefold() == host and
                   timedelta(0) <= row['when'] - process['when'] <= timedelta(minutes=correlate_minutes)]
        # Host and timestamp alone are weaker evidence than a shared PID / process GUID.
        matched = process, *related[:5]
        alerts.append(make_alert('powershell_execution_with_network_context',
            'HIGH' if related else 'MEDIUM',
            'PowerShell launched with encoded or hidden-window options.' +
            (' Nearby outbound network activity was observed from the same host, but process ownership is NOT established.'
             if related else ' No matching network events were supplied for this host/time window.'),
            list(matched), ['Check full command and parent process in endpoint telemetry.',
                             'Validate whether activity was sanctioned administration.',
                             'Correlate process GUID/PID to network event before attributing traffic.'],
            ['T1059.001 (PowerShell)'], {'host': process['host'], 'nearby_network_events': len(related)}))
    return alerts


def matching_approval(event: dict, approvals: list[dict]) -> dict | None:
    for a in approvals:
        if a['host'].casefold() != event['host'].casefold() or a['event_id'] != event['event_id']:
            continue
        if a.get('start_at') and a.get('end_at') and a['start_at'] <= event['when'] <= a['end_at']:
            return a
    return None


def detect_admin(windows: list[dict], approvals: list[dict]) -> list[dict]:
    alerts = []
    admin_rows = [row for row in windows if row['event_id'] in GROUP_IDS]
    clear_rows = [row for row in windows if row['event_id'] == '1102']
    for row in admin_rows + clear_rows:
        approval = matching_approval(row, approvals)
        near = []
        if row['event_id'] in GROUP_IDS:
            near = [e for e in clear_rows if row['host'] and e['host'].casefold() == row['host'].casefold()
                    and abs(e['when'] - row['when']) <= timedelta(minutes=30)]
        category = 'privileged_group_change' if row['event_id'] in GROUP_IDS else 'audit_log_cleared'
        severity = 'HIGH' if near else ('LOW' if approval else 'MEDIUM')
        desc = ('Privileged-group membership changed.' if row['event_id'] in GROUP_IDS else
                'A Windows Security audit log was cleared.')
        if near:
            desc += ' An audit-log-clearing event was observed on the same host within 30 minutes; validate any relationship.'
        if approval:
            desc += ' Matching approved-activity metadata exists; verify the ticket before judging the activity benign.'
        alerts.append(make_alert(category, severity, desc,
            [row] + near[:3] + ([approval] if approval else []),
            ['Check the approved change record and identity of the actor.',
             'Confirm exact event details and surrounding activity.',
             'Record a justified benign, malicious, or inconclusive verdict.'],
            ['T1098 (Account Manipulation)' if row['event_id'] in GROUP_IDS else 'T1070.001 (Clear Windows Event Logs)'],
            {'event_id': row['event_id'], 'has_approved_activity_context': bool(approval),
             'related_audit_clear_count': len(near)}))
    return alerts


def render_reports(alerts: list[dict], summary: dict[str, int], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for i, alert in enumerate(alerts, 1):
        alert['id'] = f'AUTO-{i:03d}'
    payload = {'scope': 'synthetic training data; human review required', 'input_records': summary,
               'generated_alerts': len(alerts), 'alerts': alerts}
    (output / 'correlated_alerts.json').write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    lines = ['# Northstar SOC - Automated Correlation / Triage Report', '',
             '**Training environment only.** The correlations below are leads for analyst investigation, not final verdicts.', '',
             f'Alerts: **{len(alerts)}**', '']
    for a in alerts:
        lines += [f"## {a['id']} - {a['category']} ({a['triage_priority']})", '',
                  a['interpretation'], '', '**Supporting CSV evidence:**', '']
        for e in a['evidence']:
            extra = ', '.join(f'{k}={v}' for k, v in e.items() if k not in ('ref', 'source', 'time'))
            lines.append(f"- `{e['ref']}` | {e['time']} | {extra}")
        lines += ['', '**Analyst follow-up:**', '']
        lines.extend(f'- {item}' for item in a['investigation_next_steps'])
        if a['attack_mapping_candidates']:
            lines += ['', '**Candidate MITRE ATT&CK mapping:** ' + ', '.join(a['attack_mapping_candidates'])]
        lines += ['', '**Verdict:** Pending analyst review.', '']
    (output / 'triage_report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows', required=True, type=Path, help='Windows Security CSV')
    parser.add_argument('--endpoint', type=Path, help='Optional process/Sysmon CSV')
    parser.add_argument('--network', type=Path, help='Optional outbound network CSV')
    parser.add_argument('--approved', type=Path, help='Optional approved activity CSV')
    parser.add_argument('--output', default=Path('reports'), type=Path)
    parser.add_argument('--failed-threshold', default=5, type=int)
    args = parser.parse_args(argv)
    if args.failed_threshold < 2:
        parser.error('--failed-threshold must be at least 2')
    try:
        windows = load_csv(args.windows, 'windows', ('timestamp', 'event_id', 'host'))
        endpoint = load_csv(args.endpoint, 'endpoint', ('timestamp', 'host', 'process', 'command_line'))
        network = load_csv(args.network, 'network', ('timestamp', 'host', 'destination_ip'))
        approved = load_csv(args.approved, 'approved', ('timestamp', 'host', 'event_id', 'start', 'end', 'ticket'))
        # Approved changes use start/end windows, not timestamp, for actual matching.
        windows = [w for w in windows if w['event_id'] in ALLOWED_WINDOWS_IDS]
        alerts = detect_auth(windows, threshold=args.failed_threshold)
        alerts += detect_endpoint(endpoint, network)
        alerts += detect_admin(windows, approved)
        alerts.sort(key=lambda a: a['evidence'][0]['time'] if a['evidence'] else '')
        counts = {'windows': len(windows), 'endpoint': len(endpoint),
                  'network': len(network), 'approved_activities': len(approved)}
        render_reports(alerts, counts, args.output)
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1
    print(f"Loaded {sum(counts.values())} input records. Generated {len(alerts)} triage candidates.")
    print(f'Reports: {args.output / "correlated_alerts.json"} and {args.output / "triage_report.md"}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
