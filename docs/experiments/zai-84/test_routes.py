"""Behavioral fault tests for the isolated Test-only shell hook; no live writes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HOOK = Path(__file__).with_name('test-gateway-routes')
MOCK = r'''#!/usr/bin/python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ['MOCK_STATE'])
s = json.loads(p.read_text())
name = pathlib.Path(sys.argv[0]).name
a = sys.argv[1:]
s['calls'].append([name] + a)
rc = 0
if name == 'ip':
    if a == ['-4', 'rule', 'show']: print(s.get('rules', ''))
    elif a == ['-4', 'route', 'show', 'table', 'all', 'default']:
        print(s.get('defaults', ''))
        rc = 2 if s.get('route_read_failure', False) else 0
    elif a[:3] == ['-4', 'rule', 'add']: s['rules'] = '5000:\tfrom 10.30.0.0/24 lookup 2030'
    elif a[:3] == ['link', 'show', 'dev']: rc = 0 if s.get('tun', True) else 1
elif name == 'docker': print(s.get('server_ip', '172.17.0.2'))
elif name == 'iptables' and a[0] == '-C': rc = 0 if s.get('firewall', True) else 1
p.write_text(json.dumps(s))
sys.exit(rc)
'''

@unittest.skipUnless(os.name == 'posix', 'requires POSIX sh')
class Routes(unittest.TestCase):
    def run_hook(self, mode, **state):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            state['calls'] = []
            (d / 'state').write_text(json.dumps(state))
            for name in ('ip', 'docker', 'iptables', 'sleep'):
                f = d / name
                f.write_text(MOCK)
                f.chmod(0o700)
            env = dict(os.environ, PATH=str(d) + ':' + os.environ['PATH'], MOCK_STATE=str(d / 'state'))
            result = subprocess.run(['sh', str(HOOK), mode], env=env, capture_output=True, text=True)
            return result, json.loads((d / 'state').read_text())['calls']

    def test_fallback_precedes_new_selector(self):
        result, calls = self.run_hook('guard')
        self.assertEqual(result.returncode, 0, result.stderr)
        fallback = ['ip', '-4', 'route', 'replace', 'unreachable', 'default', 'table', '2030', 'metric', '42760']
        selector = ['ip', '-4', 'rule', 'add', 'from', '10.30.0.0/24', 'lookup', '2030', 'priority', '5000']
        self.assertLess(calls.index(fallback), calls.index(selector))

    def test_existing_rule_never_added_again(self):
        result, calls = self.run_hook('tun', rules='5000:\tfrom 10.30.0.0/24 lookup 2030')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[1:4] == ['-4', 'rule', 'add'] for c in calls))
        self.assertIn(['ip', '-4', 'route', 'replace', 'default', 'dev', 'mitun0', 'table', '2030', 'metric', '100'], calls)

    def test_missing_tun_retains_fallback_and_times_out(self):
        result, calls = self.run_hook('tun', tun=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any('unreachable' in c for c in calls))
        self.assertFalse(any('replace' in c and 'mitun0' in c for c in calls))
        self.assertEqual(sum(c[0] == 'sleep' for c in calls), 19)

    def test_conflicting_rule_rejected_before_mutation(self):
        result, calls = self.run_hook('guard', rules='5000:\tfrom all lookup main')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('replace' in c or 'add' in c for c in calls))

    def test_conflicting_default_rejected(self):
        result, calls = self.run_hook('guard', defaults='default via 192.0.2.1 dev eth0 table 2030')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('replace' in c for c in calls))

    def test_existing_pair_and_management_default_accepted(self):
        defaults = ('default via 192.0.2.1 dev eth0\n'
                    'default dev mitun0 table 2030 scope link metric 100\n'
                    'unreachable default table 2030 metric 42760')
        result, calls = self.run_hook('guard', defaults=defaults)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any('192.0.2.1' in c for c in calls))

    def test_route_read_error_is_not_absence(self):
        result, calls = self.run_hook('guard', route_read_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('replace' in c or 'add' in c for c in calls))

    def test_docker_existing_firewall_not_duplicated(self):
        result, calls = self.run_hook('docker')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[:2] == ['iptables', '-I'] for c in calls))
        self.assertTrue(any('10.30.0.0/24' in c and '172.17.0.2' in c for c in calls))

    def test_docker_missing_firewall_restored(self):
        result, calls = self.run_hook('docker', firewall=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(c[:2] == ['iptables', '-I'] for c in calls), 1)

    def test_changed_container_address_blocks_route(self):
        result, calls = self.run_hook('docker', server_ip='172.17.0.99')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('via' in c for c in calls))
        self.assertEqual(sum(c[0] == 'sleep' for c in calls), 29)

    def test_unknown_mode_does_not_mutate(self):
        result, calls = self.run_hook('invalid')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, [])

if __name__ == '__main__':
    unittest.main()
