"""Host-independent tests of the real Bash operations with a fake Docker boundary."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
KEY = base64.b64encode(bytes(range(32))).decode()
PEER = base64.b64encode(bytes(range(32, 64))).decode()
CONFIG = f'''[Interface]
PrivateKey = {KEY}
Address = 10.42.0.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 10
S2 = 20
H1 = 123456
H2 = 234567
H3 = 345678
H4 = 456789

[Peer]
PublicKey = {PEER}
Endpoint = 192.0.2.2:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
'''

MOCK = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
cmd = Path(sys.argv[0]).name
args = sys.argv[1:]
root = Path(os.environ['MOCK_DIR'])
with (root / 'calls').open('a') as f: f.write(json.dumps([cmd] + args) + '\n')
statefile = root / 'containers.json'
states = json.loads(statefile.read_text()) if statefile.exists() else {}
def save(): statefile.write_text(json.dumps(states))
if cmd == 'ss':
    for p in os.environ.get('BUSY_PORTS', '').split(','):
        if p: print(f'LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:*')
elif cmd == 'flock':
    import fcntl
    fcntl.flock(int(args[-1]), fcntl.LOCK_EX)
elif cmd == 'curl':
    if '--config' in args:
        text = sys.stdin.read()
        (root / 'curl-input').write_text(text)
        if os.environ.get('FAIL_CHECK'): sys.exit(7)
        print('203.0.113.17')
    else:
        if os.environ.get('FAIL_METRICS'): sys.exit(7)
        print('private_key=REDACTED\npublic_key=unused\nrx_bytes=1048576\ntx_bytes=2097152\nlast_handshake_time_sec=1')
elif cmd == 'docker':
    if args[0] == 'inspect':
        name = args[-1]
        if name not in states: sys.exit(1)
        if '--format' in args:
            print('2026-01-01T00:00:00Z' if 'StartedAt' in args[args.index('--format')+1] else states[name])
        else: print('{}')
    elif args[0] == 'image':
        if os.environ.get('NO_IMAGE'): sys.exit(1)
    elif args[0] == 'pull':
        if os.environ.get('FAIL_PULL'): sys.exit(1)
    elif args[0] == 'run':
        if os.environ.get('FAIL_VALIDATE'):
            print('invalid base64 key: ' + os.environ['TEST_KEY'])
            sys.exit(1)
    elif args[0] == 'compose' and '--file' in args:
        config = json.loads(Path(args[args.index('--file')+1]).read_text())
        name = config['services']['proxy']['container_name']
        if 'up' in args:
            if os.environ.get('FAIL_UP'): sys.exit(1)
            states[name] = 'running'
        elif 'stop' in args: states[name] = 'exited'
        elif 'down' in args:
            if os.environ.get('FAIL_DOWN'): sys.exit(1)
            states.pop(name, None)
        save()
    elif args[0] == 'stats':
        for name in args[4:]:
            if states.get(name) == 'running': print(json.dumps({'Name': name, 'CPUPerc': '0.3%', 'MemUsage':'24MiB / 2GiB'}))
    elif args[0] == 'logs': print('example log')
'''

class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.data = self.base / 'data'
        (self.data / 'profiles').mkdir(parents=True)
        (self.data / 'host').write_text('192.0.2.1\n')
        self.mock = self.base / 'mocks'
        self.mock.mkdir()
        script = self.mock / 'mock.py'
        script.write_text(MOCK)
        script.chmod(0o755)
        for name in ['docker', 'curl', 'ss', 'flock']:
            (self.mock / name).symlink_to(script)
        self.env = dict(os.environ, PATH=f'{self.mock}:{os.environ["PATH"]}',
                        MOCK_DIR=str(self.mock), TEST_KEY=KEY)
        self.fixture = self.base / 'input with spaces.conf'
        self.fixture.write_text(CONFIG)

    def tearDown(self):
        self.tmp.cleanup()

    def run_core(self, *args, input=None, env=None):
        # Isolate host preflight; execute unchanged production operations.
        source = '''set -Eeuo pipefail
umask 077
APP_DIR=$1; DATA_DIR=$2; shift 2
ENGINE_IMAGE=example/wireproxy:test
CHECK_URL=https://api.ipify.org
source "$APP_DIR/lib/core.sh"
source "$APP_DIR/lib/menu.sh"
"$@"
'''
        return subprocess.run(['bash', '-c', source, 'test', str(ROOT), str(self.data), *args],
                              input=input, text=True, capture_output=True,
                              env=dict(self.env, **(env or {})))

    def add(self, name='alice', **kwargs):
        return self.run_core('add_profile', name, str(self.fixture), **kwargs)

    def profile(self, name='alice'):
        return self.data / 'profiles' / name

    def calls(self):
        file = self.mock / 'calls'
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_add_file_auth_local_metrics_and_permissions(self):
        result = self.add()
        self.assert_ok(result)
        meta = json.loads((self.profile() / 'profile.json').read_text())
        self.assertEqual(meta['port'], 11001)
        self.assertEqual(meta['metrics_port'], 31001)
        self.assertRegex(meta['password'], r'^[0-9a-f]{48}$')
        self.assertNotIn(meta['password'], result.stdout)
        config = (self.profile() / 'wireproxy.conf').read_text()
        self.assertIn('Username = alice', config)
        self.assertIn('Password = ' + meta['password'], config)
        self.assertIn('ListenPort = 0', config)
        compose = json.loads((self.profile() / 'compose.json').read_text())['services']['proxy']
        self.assertEqual(compose['network_mode'], 'host')
        self.assertIn('127.0.0.1:31001', compose['command'])
        self.assertTrue(compose['read_only'])
        self.assertEqual(compose['cap_drop'], ['ALL'])
        for file in self.profile().iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.profile().stat().st_mode & 0o777, 0o700)
        self.assertNotIn(meta['password'], json.dumps(self.calls()))
        self.assertIn(meta['password'], (self.mock / 'curl-input').read_text())

    def test_paste_and_file_produce_same_tunnel(self):
        result = self.run_core('add_profile', 'alice', input=CONFIG + '\n\n')
        self.assert_ok(result)
        self.assertIn('Jc = 4', (self.profile() / 'awg.conf').read_text())

    def test_paste_ends_on_two_blank_lines_and_keeps_section_separator(self):
        result = self.run_core('add_profile', 'alice', input=CONFIG + '\n\n')
        self.assert_ok(result)
        config = (self.profile() / 'awg.conf').read_text()
        self.assertIn('[Peer]', config)
        self.assertIn('PersistentKeepalive = 25', config)
        self.assertIn('Jc = 4', config)

    def test_paste_accepts_crlf_and_whitespace_blank_lines(self):
        result = self.run_core('add_profile', 'alice',
                               input=CONFIG.replace('\n', '\r\n') + ' \r\n\t\r\n')
        self.assert_ok(result)
        self.assertIn('[Peer]', (self.profile() / 'awg.conf').read_text())

    def test_empty_paste_creates_nothing(self):
        result = self.run_core('add_profile', 'alice', input='\n\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list((self.data / 'profiles').iterdir()), [])

    def test_truncated_paste_creates_nothing(self):
        result = self.run_core('add_profile', 'alice', input=CONFIG)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list((self.data / 'profiles').iterdir()), [])

    def test_duplicate_key_rejected_and_other_profile_unchanged(self):
        self.assert_ok(self.add())
        before = (self.profile() / 'profile.json').read_bytes()
        result = self.add('bob')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.profile('bob').exists())
        self.assertEqual(before, (self.profile() / 'profile.json').read_bytes())

    def test_menu_accepts_olm_after_rejecting_cyrillic_lookalike(self):
        result = self.run_core('eval', 'run_action() { shift; add_profile "$@"; }; add_menu',
                               input='оlm\nolm\n1\n\n' + CONFIG + '\n\n')
        self.assert_ok(result)
        self.assertTrue(self.profile('olm').exists())
        self.assertFalse(self.profile('оlm').exists())
        self.assertIn('некорректное имя', result.stderr)
        self.assertIn(r'\320\276', result.stderr)
        self.assertIn('Вставьте AWG-конфиг', result.stdout)

    def test_bad_names_never_escape_profiles(self):
        for name in ['../alice', '/tmp/alice', 'Alice', '-bad', 'a;touch pwn', 'a' * 33]:
            self.assertNotEqual(self.add(name).returncode, 0)
        self.assertFalse(self.calls())

    def test_ports_skip_host_listeners_and_stopped_profiles(self):
        self.assert_ok(self.add(env={'BUSY_PORTS': '11001,31001'}))
        self.assert_ok(self.run_core('lifecycle', 'stop', 'alice'))
        self.fixture.write_text(CONFIG.replace(KEY, base64.b64encode(b'z' * 32).decode()))
        self.assert_ok(self.add('bob', env={'BUSY_PORTS': '11001,31001'}))
        meta = json.loads((self.profile('bob') / 'profile.json').read_text())
        self.assertEqual(meta['port'], 11003)
        self.assertEqual(meta['metrics_port'], 31003)

    def test_explicit_port_and_metric_port_do_not_overlap(self):
        self.assert_ok(self.run_core('add_profile', 'alice', str(self.fixture), '--port', '31001'))
        meta = json.loads((self.profile() / 'profile.json').read_text())
        self.assertEqual(meta['port'], 31001)
        self.assertEqual(meta['metrics_port'], 31002)

    def test_invalid_or_busy_ports_rejected(self):
        for port in ['22', '65536', '01080', '1234x', '$(touch pwn)', '11001']:
            result = self.run_core('add_profile', 'alice', str(self.fixture), '--port', port,
                                   env={'BUSY_PORTS': '11001'})
            self.assertNotEqual(result.returncode, 0, port)
        self.assertFalse(self.profile().exists())

    def test_validation_failure_redacts_keys_and_cleans_up(self):
        result = self.add(env={'FAIL_VALIDATE': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(KEY, result.stdout + result.stderr)
        self.assertIn('[KEY REDACTED]', result.stderr)
        self.assertEqual(list((self.data / 'profiles').iterdir()), [])

    def test_failed_pull_cannot_commit_profile(self):
        result = self.add(env={'NO_IMAGE': '1', 'FAIL_PULL': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.profile().exists())

    def test_failed_check_is_failure_but_retains_profile(self):
        result = self.add(env={'FAIL_CHECK': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.profile().exists())
        self.assertNotIn(': OK', result.stdout)

    def test_failed_up_retains_configuration_for_retry(self):
        self.assertNotEqual(self.add(env={'FAIL_UP': '1'}).returncode, 0)
        self.assertTrue(self.profile().exists())
        self.assert_ok(self.run_core('lifecycle', 'start', 'alice'))

    def test_start_rejects_occupied_port(self):
        self.assert_ok(self.add())
        self.assert_ok(self.run_core('lifecycle', 'stop', 'alice'))
        result = self.run_core('lifecycle', 'start', 'alice', env={'BUSY_PORTS': '31001'})
        self.assertNotEqual(result.returncode, 0)

    def test_remove_needs_confirmation_and_down_success(self):
        self.assert_ok(self.add())
        self.assertNotEqual(self.run_core('remove_profile', 'alice').returncode, 0)
        self.assertTrue(self.profile().exists())
        self.assertNotEqual(self.run_core('remove_profile', 'alice', '--yes', env={'FAIL_DOWN': '1'}).returncode, 0)
        self.assertTrue(self.profile().exists())
        self.assert_ok(self.run_core('remove_profile', 'alice', '--yes'))
        self.assertFalse(self.profile().exists())

    def test_stop_start_and_check(self):
        self.assert_ok(self.add())
        self.assert_ok(self.run_core('lifecycle', 'stop', 'alice'))
        self.assertNotEqual(self.run_core('check_one', 'alice').returncode, 0)
        self.assert_ok(self.run_core('lifecycle', 'start', 'alice'))
        self.assert_ok(self.run_core('check_one', 'alice'))

    def test_stats_handles_stopped_and_unavailable_metrics(self):
        self.assert_ok(self.add())
        result = self.run_core('stats_snapshot')
        self.assert_ok(result)
        self.assertIn('1.00', result.stdout)
        self.assertIn('2.00', result.stdout)
        self.assertNotIn(KEY, result.stdout)
        result = self.run_core('stats_snapshot', env={'FAIL_METRICS': '1'})
        self.assert_ok(result)
        self.assertIn('unavailable', result.stdout)
        self.assert_ok(self.run_core('lifecycle', 'stop', 'alice'))
        result = self.run_core('stats_snapshot')
        self.assert_ok(result)
        self.assertIn('exited', result.stdout)

    def test_other_profiles_not_restarted_or_removed(self):
        self.assert_ok(self.add())
        self.fixture.write_text(CONFIG.replace(KEY, base64.b64encode(b'z' * 32).decode()))
        self.assert_ok(self.add('bob'))
        before = (self.profile('bob') / 'wireproxy.conf').read_bytes()
        self.assert_ok(self.run_core('remove_profile', 'alice', '--yes'))
        self.assertEqual(before, (self.profile('bob') / 'wireproxy.conf').read_bytes())
        states = json.loads((self.mock / 'containers.json').read_text())
        self.assertEqual(states['socks2awg-bob'], 'running')

    def test_show_reveals_only_socks_password(self):
        self.assert_ok(self.add())
        result = self.run_core('show_profile', 'alice')
        self.assert_ok(result)
        self.assertIn('socks5h://alice:', result.stdout)
        self.assertNotIn(KEY, result.stdout)

class ConfigTest(unittest.TestCase):
    def normalize(self, text):
        return subprocess.run(['awk', '-f', str(ROOT / 'lib/normalize.awk')], input=text,
                              text=True, capture_output=True)

    def test_import_crlf_and_new_awg_parameters(self):
        text = CONFIG.replace('Jc = 4', 'Jc = 4\nI1 = <b 0xc000><r 12>\nH1 = 9')
        # Duplicate H1 must fail, not silently change semantics.
        self.assertNotEqual(self.normalize(text).returncode, 0)
        text = CONFIG.replace('Jc = 4', 'Jc = 4\nI1 = <b 0xc000><r 12>\nRandomTrailers = on')
        result = self.normalize(text.replace('\n', '\r\n'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('I1 = <b 0xc000><r 12>', result.stdout)

    def test_missing_dns_is_routed_via_tunnel(self):
        result = self.normalize(CONFIG.replace('DNS = 1.1.1.1\n', ''))
        self.assertEqual(result.returncode, 0)
        self.assertIn('DNS = 1.1.1.1', result.stdout)

    def test_hooks_unknown_keys_extra_sections_and_multipeer_rejected(self):
        bad = [CONFIG + '\n[Socks5]\nBindAddress=0.0.0.0:9999\n',
               CONFIG + '\n[Peer]\nPublicKey=' + PEER,
               CONFIG.replace('Jc = 4', 'PostUp = touch /tmp/owned'),
               CONFIG.replace('Jc = 4', 'Jccc = 4'),
               CONFIG.replace(KEY, '$SECRET'),
               CONFIG.replace('Jc = 4', 'Jc = $(touch /tmp/owned)'),
               CONFIG.replace('0.0.0.0/0', '10.0.0.0/8')]
        for text in bad:
            result = self.normalize(text)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(KEY, result.stderr)

    def test_host_only_settings_removed(self):
        result = self.normalize(CONFIG.replace('Jc = 4', 'Jc = 4\nListenPort=51820\nTable=auto\nSaveConfig=true'))
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('51820\n', result.stdout.split('[Peer]')[0])
        self.assertNotIn('Table', result.stdout)
        self.assertNotIn('SaveConfig', result.stdout)

    def test_help_without_docker_or_root(self):
        result = subprocess.run([str(ROOT / 'socks2awg'), 'help'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('edit NAME', result.stdout)

if __name__ == '__main__':
    unittest.main()
