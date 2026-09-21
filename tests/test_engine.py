"""Real SOCKS -> AWG -> HTTPS round trip, using only local disposable peers.

WIREPROXY_BINARY=/path/to/wireproxy python3 tests/test_engine.py
On Linux with Docker (root): WIREPROXY_IMAGE=... python3 tests/test_engine.py
The Docker variant exercises the installed CLI's actual add/check/stats/remove flow.
"""
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get('WIREPROXY_BINARY')
IMAGE = os.environ.get('WIREPROXY_IMAGE')
AWG = '''Jc = 4
Jmin = 40
Jmax = 70
S1 = 10
S2 = 20
H1 = 123456
H2 = 234567
H3 = 345678
H4 = 456789
'''

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'203.0.113.17'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def free_port(udp=False):
    with socket.socket(type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


@unittest.skipUnless(BINARY or IMAGE, 'set WIREPROXY_BINARY or WIREPROXY_IMAGE for real engine test')
class RealEngineTest(unittest.TestCase):
    def test_authenticated_socks_over_awg(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            processes = []
            logs = []
            server_name = f'socks2awg-test-peer-{os.getpid()}'
            name = f'test-{os.getpid()}'
            cli = [os.environ.get('SOCKS2AWG_CLI', str(ROOT / 'socks2awg'))]
            env = dict(os.environ, SOCKS2AWG_DATA_DIR=str(root / 'data'),
                       SOCKS2AWG_CHECK_URL='https://10.85.0.1:8443',
                       CURL_CA_BUNDLE=str(root / 'cert.pem'))
            httpd = None
            try:
                def keypair(label):
                    path = root / f'{label}.pem'
                    command(['openssl', 'genpkey', '-algorithm', 'X25519', '-out', str(path)])
                    private = command(['openssl', 'pkey', '-in', str(path), '-outform', 'DER'])[-32:]
                    public = command(['openssl', 'pkey', '-in', str(path), '-pubout', '-outform', 'DER'])[-32:]
                    return base64.b64encode(private).decode(), base64.b64encode(public).decode()

                client_key, client_pub = keypair('client')
                server_key, server_pub = keypair('server')
                command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                         '-keyout', str(root / 'tls-key.pem'), '-out', str(root / 'cert.pem'),
                         '-subj', '/CN=10.85.0.1', '-addext', 'subjectAltName=IP:10.85.0.1'])
                httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / 'cert.pem', root / 'tls-key.pem')
                httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                threading.Thread(target=httpd.serve_forever, daemon=True).start()
                udp_port = free_port(udp=True)
                socks_port = free_port()
                metrics_port = free_port()
                server_conf = root / 'server.conf'
                server_conf.write_text(f'''[Interface]
PrivateKey = {server_key}
Address = 10.85.0.1/24
ListenPort = {udp_port}
{AWG}
[Peer]
PublicKey = {client_pub}
AllowedIPs = 10.85.0.2/32

[TCPServerTunnel]
ListenPort = 8443
Target = 127.0.0.1:{httpd.server_port}
''')
                client_conf = root / 'client.conf'
                client_conf.write_text(f'''[Interface]
PrivateKey = {client_key}
Address = 10.85.0.2/32
DNS = 1.1.1.1
{AWG}
[Peer]
PublicKey = {server_pub}
Endpoint = 127.0.0.1:{udp_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
''')
                for path in [server_conf, client_conf]:
                    path.chmod(0o600)

                def launch(label, config, extra):
                    log = (root / f'{label}.log').open('w+')
                    logs.append(log)
                    if IMAGE:
                        args = ['docker', 'run', '--rm', '--name', server_name, '--network', 'host',
                                '--user', '0:0', '--read-only', '--cap-drop', 'ALL',
                                '--security-opt', 'no-new-privileges:true',
                                '--mount', f'type=bind,src={config},dst=/etc/config,readonly',
                                IMAGE, '-s', '-c', '/etc/config', *extra]
                    else:
                        args = [BINARY, '-s', '-c', str(config), *extra]
                    process = subprocess.Popen(args, stdout=log, stderr=log)
                    processes.append(process)
                    return process

                launch('server', server_conf, [])
                # Server may take a moment to load its userspace stack.
                time.sleep(1)
                if IMAGE:
                    data = root / 'data'
                    data.mkdir()
                    (data / 'host').write_text('127.0.0.1\n')
                    result = subprocess.run([*cli, 'add', name, str(client_conf), '--port', str(socks_port)],
                                            env=env, text=True, capture_output=True, timeout=70)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    meta = json.loads((data / 'profiles' / name / 'profile.json').read_text())
                    password = meta['password']
                    username = name
                    metrics_port = meta['metrics_port']
                    for action in ['check', 'stats', 'show']:
                        result = subprocess.run([*cli, action, name], env=env, text=True, capture_output=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    username, password = 'alice', 'test-only-strong-password-1234567890'
                    normalized = command(['awk', '-f', str(ROOT / 'lib/normalize.awk'), str(client_conf)], text=True)
                    client_conf.write_text(normalized + f'\n[Socks5]\nBindAddress = 127.0.0.1:{socks_port}\nUsername = {username}\nPassword = {password}\n')
                    command([BINARY, '-n', '-c', str(client_conf)])
                    launch('client', client_conf, ['-i', f'127.0.0.1:{metrics_port}'])
                curl = ['curl', '-q', '--silent', '--show-error', '--fail', '--noproxy', '',
                        '--connect-timeout', '2', '--max-time', '5',
                        '--proxy', f'socks5h://127.0.0.1:{socks_port}', '--cacert', str(root / 'cert.pem')]
                # Retry only startup; failures later in the test are not hidden.
                deadline = time.monotonic() + 15
                while True:
                    result = subprocess.run([*curl, '--proxy-user', f'{username}:{password}',
                                             'https://10.85.0.1:8443'], text=True, capture_output=True)
                    if result.returncode == 0 or time.monotonic() >= deadline:
                        break
                    time.sleep(0.2)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '203.0.113.17')
                wrong = subprocess.run([*curl, '--proxy-user', f'{username}:wrong-password',
                                        'https://10.85.0.1:8443'], text=True, capture_output=True)
                self.assertNotEqual(wrong.returncode, 0, 'Wrong password was accepted')
                noauth = subprocess.run([*curl, 'https://10.85.0.1:8443'], text=True, capture_output=True)
                self.assertNotEqual(noauth.returncode, 0, 'Unauthenticated SOCKS was accepted')
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                metrics = opener.open(f'http://127.0.0.1:{metrics_port}/metrics', timeout=3).read().decode()
                self.assertNotIn(client_key, metrics)
                fields = dict(line.split('=', 1) for line in metrics.splitlines() if '=' in line)
                self.assertGreater(int(fields['rx_bytes']), 0)
                self.assertGreater(int(fields['tx_bytes']), 0)
                self.assertGreater(int(fields['last_handshake_time_sec']), 0)
                self.assertEqual(fields['private_key'], 'REDACTED')
                if IMAGE:
                    if os.environ.get('SOCKS2AWG_TEST_REINSTALL'):
                        metadata_path = Path(env['SOCKS2AWG_DATA_DIR']) / 'profiles' / name / 'profile.json'
                        before = metadata_path.read_bytes()
                        started = command(['docker', 'inspect', '--format', '{{.State.StartedAt}}', f'socks2awg-{name}'])
                        command(['bash', str(ROOT / 'install.sh'), '--from', str(ROOT)])
                        self.assertEqual(before, metadata_path.read_bytes())
                        self.assertEqual(started, command(['docker', 'inspect', '--format', '{{.State.StartedAt}}', f'socks2awg-{name}']))
                    for action in ['stop', 'start']:
                        command([*cli, action, name], env=env)
                    command([*cli, 'check', name], env=env)
            finally:
                if IMAGE:
                    subprocess.run([*cli, 'remove', name, '--yes'], env=env, capture_output=True, timeout=30)
                    subprocess.run(['docker', 'rm', '-f', server_name], capture_output=True, timeout=30)
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                if httpd:
                    httpd.shutdown()
                    httpd.server_close()
                for log in logs:
                    log.close()

if __name__ == '__main__':
    unittest.main()
