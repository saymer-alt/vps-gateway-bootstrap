"""Behavioral fault tests for the isolated Test-only shell hook; no live writes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import configparser

HOOK = Path(__file__).with_name('test-gateway-routes')
BASE_RULES = '0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default'
EGRESS = '-A FORWARD -s 10.30.0.0/24 ! -o mitun0 -m comment --comment ZAI85-client-failclosed -j DROP'
MOCK = r'''#!/usr/bin/python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ['MOCK_STATE'])
s = json.loads(p.read_text())
name = pathlib.Path(sys.argv[0]).name
a = sys.argv[1:]
s['calls'].append([name] + a)
if [name] + a == s.get('fail_command'):
    p.write_text(json.dumps(s)); sys.exit(2)
rc = 0
if name == 'ip':
    if a == ['-4', 'rule', 'show']: print(s.get('rules', ''))
    elif a == ['-4', 'route', 'show', 'table', 'all']:
        print(s.get('defaults', ''))
        rc = 2 if s.get('route_read_failure', False) else 0
    elif a[:3] == ['-4', 'rule', 'add']: s['rules'] += '\n5000:\tfrom 10.30.0.0/24 lookup 2030'
    elif a[:3] == ['link', 'show', 'dev']: rc = 0 if s.get('tun', True) else 1
elif name == 'docker':
    if a[0] == 'start': print('awg-client-test')
    elif 'RestartPolicy' in a[2]: print(s.get('client_policy', 'no'))
    elif a[-1] == 'awg-client-test': print(s.get('client_ip', '172.17.0.3'))
    else: print(s.get('server_ip', '172.17.0.2'))
elif name == 'iptables':
    if 'mangle' in a:
        if '-C' in a: rc = 0 if s.get('egress_present', True) else 1
        elif '-I' in a: s['egress_present'] = True
        elif '-S' in a:
            print('-P FORWARD ACCEPT')
            if s.get('preempt_guard', False): print('-A FORWARD -j ACCEPT')
            print('-A FORWARD -s 10.30.0.0/24 ! -o mitun0 -m comment --comment ZAI85-client-failclosed -j DROP')
    elif '-C' in a: rc = 0 if s.get('firewall', True) else 1
    elif '-I' in a: s['firewall'] = True
p.write_text(json.dumps(s))
sys.exit(rc)
'''

@unittest.skipUnless(os.name == 'posix', 'requires POSIX sh')
class Routes(unittest.TestCase):
    def run_hook(self, mode, repeat=1, **state):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            state['calls'] = []
            state.setdefault('rules', BASE_RULES)
            (d / 'state').write_text(json.dumps(state))
            for name in ('ip', 'docker', 'iptables', 'sleep'):
                f = d / name
                f.write_text(MOCK)
                f.chmod(0o700)
            env = dict(os.environ, PATH=str(d) + ':' + os.environ['PATH'], MOCK_STATE=str(d / 'state'))
            for _ in range(repeat):
                result = subprocess.run([str(HOOK), mode], env=env, capture_output=True, text=True)
                if result.returncode:
                    break
            return result, json.loads((d / 'state').read_text())['calls']

    def test_fallback_precedes_new_selector(self):
        result, calls = self.run_hook('guard')
        self.assertEqual(result.returncode, 0, result.stderr)
        fallback = ['ip', '-4', 'route', 'replace', 'unreachable', 'default', 'table', '2030', 'metric', '42760']
        selector = ['ip', '-4', 'rule', 'add', 'from', '10.30.0.0/24', 'lookup', '2030', 'priority', '5000']
        self.assertLess(calls.index(fallback), calls.index(selector))

    def test_existing_rule_never_added_again(self):
        result, calls = self.run_hook('tun', rules=BASE_RULES + '\n5000:\tfrom 10.30.0.0/24 lookup 2030')
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
        self.assertFalse(any(c[0] == 'iptables' and '-I' in c for c in calls))
        self.assertTrue(any('10.30.0.0/24' in c and '172.17.0.2' in c for c in calls))

    def test_docker_missing_firewall_restored(self):
        result, calls = self.run_hook('docker', firewall=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(c[0] == 'iptables' and '-I' in c for c in calls), 1)

    def test_changed_container_address_blocks_route(self):
        result, calls = self.run_hook('docker', server_ip='172.17.0.99')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('via' in c for c in calls))
        self.assertEqual(sum(c[0] == 'sleep' for c in calls), 29)

    def test_unknown_mode_does_not_mutate(self):
        result, calls = self.run_hook('invalid')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, [])

    def test_client_started_only_after_server_address_verified(self):
        result, calls = self.run_hook('docker')
        self.assertEqual(result.returncode, 0, result.stderr)
        start = calls.index(['docker', 'start', 'awg-client-test'])
        server = next(i for i, c in enumerate(calls) if c[0] == 'docker' and c[-1] == 'awg-server-test')
        route = next(i for i, c in enumerate(calls) if 'via' in c)
        self.assertLess(server, start)
        self.assertLess(start, route)
        for state in ({'server_ip': '172.17.0.99'}, {'client_policy': 'unless-stopped'}):
            result, calls = self.run_hook('docker', **state)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(['docker', 'start', 'awg-client-test'], calls)

    def test_wrong_client_address_blocks_reverse_route(self):
        result, calls = self.run_hook('docker', client_ip='172.17.0.99')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('via' in c for c in calls))

    def test_specific_route_in_protected_table_rejected(self):
        result, calls = self.run_hook('guard', defaults='1.1.1.1 via 192.0.2.1 dev ens3 table 2030')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('replace' in c or 'add' in c for c in calls))

    def test_preempting_and_malformed_policy_rules_rejected(self):
        for extra in ('4000: from 10.30.0.0/24 lookup main', '40: from all fwmark 0x88 lookup main',
                      '5000: from all lookup main', 'bad rule',
                      '5000: from 10.30.0.0/24 lookup 2030\n5000: from 10.30.0.0/24 lookup 2030'):
            with self.subTest(extra=extra):
                result, calls = self.run_hook('guard', rules=BASE_RULES + '\n' + extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any('replace' in c or 'add' in c for c in calls))

    def test_fallback_route_failure_blocks_selector(self):
        failed = ['ip', '-4', 'route', 'replace', 'unreachable', 'default', 'table', '2030', 'metric', '42760']
        result, calls = self.run_hook('guard', fail_command=failed)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c[1:4] == ['-4', 'rule', 'add'] for c in calls))

    def test_tun_route_command_failure_propagates(self):
        failed = ['ip', '-4', 'route', 'replace', 'default', 'dev', 'mitun0', 'table', '2030', 'metric', '100']
        result, calls = self.run_hook('tun', fail_command=failed)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any('unreachable' in c for c in calls))

    def test_egress_guard_precedes_selector_and_is_idempotent(self):
        result, calls = self.run_hook('guard', repeat=3, egress_present=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        inserts = [i for i, c in enumerate(calls) if c[0] == 'iptables' and '-I' in c]
        selectors = [i for i, c in enumerate(calls) if c[1:4] == ['-4', 'rule', 'add']]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(len(selectors), 1)
        self.assertLess(inserts[0], selectors[0])

    def test_egress_guard_error_blocks_routing(self):
        failed = ['iptables', '-w', '5', '-t', 'mangle', '-C', 'FORWARD', '-s', '10.30.0.0/24', '!', '-o', 'mitun0', '-m', 'comment', '--comment', 'ZAI85-client-failclosed', '-j', 'DROP']
        result, calls = self.run_hook('guard', fail_command=failed)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('replace' in c or 'add' in c or '-I' in c for c in calls))

    def test_preempted_egress_guard_rejected(self):
        result, calls = self.run_hook('guard', preempt_guard=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('replace' in c or 'add' in c for c in calls))

    def test_docker_repeated_hook_execution(self):
        result, calls = self.run_hook('docker', repeat=3, firewall=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(c[0] == 'iptables' and '-I' in c for c in calls), 1)
        self.assertEqual(sum(c[1:4] == ['-4', 'rule', 'add'] for c in calls), 1)

    def test_ufw_reload_hook_only_reasserts_firewall(self):
        result, calls = self.run_hook('firewall', repeat=2, egress_present=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(c[0] == 'iptables' and '-I' in c for c in calls), 1)
        self.assertFalse(any(c[0] in ('ip', 'docker') for c in calls))

    def test_git_tracks_executable_hook(self):
        root = Path(__file__).resolve().parents[3]
        result = subprocess.run(['git', '-C', str(root), 'ls-files', '-s', '--',
                                 'docs/experiments/zai-84/test-gateway-routes'], capture_output=True, text=True, check=True)
        self.assertTrue(result.stdout.startswith('100755 '), result.stdout)

    def test_startup_ordering_and_isolated_docker_failure(self):
        def unit(name):
            config = configparser.ConfigParser(strict=False)
            config.read(HOOK.with_name(name))
            return config
        guard = unit('test-routing-guard.service')
        docker = unit('docker-zai84.conf')
        awg = unit('test-awg-return.service')
        mihomo = unit('test-mihomo.service')
        restore = unit('test-route-restore.service')
        self.assertIn('ufw.service', guard['Unit']['After'].split())
        self.assertIn('test-routing-guard.service', docker['Unit']['Requires'].split())
        self.assertIn('test-routing-guard.service', docker['Unit']['After'].split())
        self.assertNotIn('Service', docker)  # AWG failure cannot kill Docker via ExecStartPost.
        self.assertIn('docker.service', awg['Unit']['After'].split())
        self.assertIn('docker.service', awg['Unit']['PartOf'].split())
        self.assertEqual(awg['Service']['ExecStop'], '/usr/bin/docker stop --time 5 awg-client-test')
        self.assertEqual(awg['Service']['TimeoutStopSec'], '15')
        self.assertIn('test-routing-guard.service', mihomo['Unit']['Requires'].split())
        self.assertTrue(mihomo['Service']['ExecStartPost'].endswith(' tun'))
        self.assertEqual(mihomo['Service']['Restart'], 'always')
        self.assertEqual(restore['Unit']['After'], 'test-mihomo.service')
        # The actual units are also checked by systemd-analyze on Test.

if __name__ == '__main__':
    unittest.main()
