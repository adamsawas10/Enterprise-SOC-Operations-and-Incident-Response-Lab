import sys
from pathlib import Path
import unittest
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from soc_correlator import detect_admin, detect_auth, detect_endpoint, load_csv, parse_time, main

DATA = ROOT

def row(date, eid='', host='NS-DC01', username='jdoe', ip='192.0.2.44', ref='windows:2'):
    return {'when': parse_time(date), 'event_id': eid, 'host': host, 'username': username,
            'source_ip': ip, 'ref': ref, 'source': 'windows', 'process': '',
            'command_line': '', 'destination_ip': '', 'destination_port': ''}

class CorrelatorTests(unittest.TestCase):
    def test_parse_time_requires_explicit_timezone(self):
        with self.assertRaises(ValueError):
            parse_time('2026-10-01 09:00:00')
        self.assertEqual(parse_time('2026-10-01T09:00:00Z').tzinfo, timezone.utc)

    def test_original_auth_case_nine_failures_no_success(self):
        events = load_csv(DATA / 'windows.csv', 'windows', ('timestamp','event_id','host'))
        findings = [a for a in detect_auth(events) if a['category'] == 'repeated_failed_authentication']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['details']['failure_count'], 9)
        self.assertFalse(findings[0]['details']['successful_authentication_observed'])

    def test_success_after_five_failures(self):
        events = [row(f'2026-10-01T09:{i:02}:00Z','4625') for i in range(5)]
        events.append(row('2026-10-01T09:06:00Z', '4624', ref='windows:7'))
        alerts = detect_auth(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['category'], 'success_after_failed_authentication')
        self.assertEqual(alerts[0]['triage_priority'], 'HIGH')
        self.assertEqual(len(alerts[0]['evidence']), 6)

    def test_no_cross_user_auth_match(self):
        events = [row(f'2026-10-01T09:{i:02}:00Z','4625') for i in range(5)]
        events.append(row('2026-10-01T09:06:00Z', '4624', username='different'))
        alerts = detect_auth(events)
        self.assertEqual(alerts[0]['category'], 'repeated_failed_authentication')

    def test_powershell_host_only_correlation_qualified(self):
        e = load_csv(DATA / 'endpoint.csv','endpoint',('timestamp','host','process','command_line'))
        n = load_csv(DATA / 'network.csv','network',('timestamp','host','destination_ip'))
        alerts = detect_endpoint(e,n)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['triage_priority'], 'HIGH')
        self.assertIn('NOT established', alerts[0]['interpretation'])

    def test_approved_audit_clear_never_automatically_closed(self):
        w = load_csv(DATA / 'windows.csv','windows',('timestamp','event_id','host'))
        a = load_csv(DATA / 'approved_activities.csv','approved',('timestamp','host','event_id','start','end','ticket'))
        alerts = detect_admin(w,a)
        log_clear = next(x for x in alerts if x['category'] == 'audit_log_cleared')
        self.assertEqual(log_clear['triage_priority'], 'LOW')
        self.assertEqual(log_clear['analyst_verdict'], 'REVIEW_REQUIRED')
        self.assertTrue(log_clear['details']['has_approved_activity_context'])

    def test_no_false_detection_when_failures_spread_out(self):
        # All consecutive gaps are below 10 minutes, but no 10-minute
        # window contains 5 attempts: do not call this a burst.
        events = [row(f'2026-10-01T09:{i:02}:00Z', '4625') for i in (0, 8, 16, 24, 32)]
        self.assertEqual(detect_auth(events), [])

    def test_missing_auth_ip_not_conflated(self):
        events = [row(f'2026-10-01T09:{i:02}:00Z','4625', ip='') for i in range(7)]
        self.assertEqual(detect_auth(events), [])

    def test_admin_and_clear_same_host_escalates_priority(self):
        e = [row('2026-10-01T09:00:00Z','4728'), row('2026-10-01T09:10:00Z','1102')]
        alerts = detect_admin(e,[])
        self.assertEqual(alerts[0]['triage_priority'], 'HIGH')
        self.assertEqual(len(alerts[0]['evidence']), 2)

if __name__ == '__main__':
    unittest.main()
