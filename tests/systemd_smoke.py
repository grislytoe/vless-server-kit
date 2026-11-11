"""Disposable GitHub runner ONLY: real services, Unix permissions, HTTPS and CRUD.

This intentionally writes fixed system paths. Never run on a user's VPS.
"""
import grp
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import DEFAULTS, new_credentials, server_config, write
from panel_setup import password_hash
from panel import rpc
from probe import available_port


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True)


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('VLESS_SYSTEMD_SMOKE') != '1' or os.geteuid() != 0:
        raise SystemExit('Only allowed as root on an explicitly enabled disposable GitHub runner.')
    state = Path('/var/lib/vless-optimized')
    target = Path('/opt/vless-optimized')
    if state.exists() or target.exists():
        raise SystemExit('Refusing to touch an existing managed server.')
    base = Path(__file__).resolve().parents[1]
    state.mkdir(mode=0o700)
    run('groupadd', '--system', 'vless-admin')
    run('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'vless-panel')
    run('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'xray')
    target.mkdir(mode=0o755)
    for name in ('config.py', 'admin.py', 'panel.py', 'panel_setup.py'):
        shutil.copyfile(base / name, target / name)
    for name in ('templates', 'static'):
        shutil.copytree(base / name, target / name)
    shutil.copyfile(os.environ['XRAY_TEST_BIN'], '/usr/local/bin/xray')
    os.chmod('/usr/local/bin/xray', 0o755)
    s = dict(DEFAULTS, domain='vpn.example.test', inbound_ip='127.0.0.1', outbound_ip='127.0.0.2',
             port=available_port(), fallback_port=available_port(), fingerprint='chrome',
             panel_path='/manage-' + secrets.token_hex(16))
    c = new_credentials('/usr/local/bin/xray')
    write(state / 'settings.json', s)
    write(state / 'credentials.json', c)
    directory = Path('/usr/local/etc/xray')
    directory.mkdir(parents=True, mode=0o750)
    os.chown(directory, 0, grp.getgrnam('xray').gr_gid)
    write(directory / 'config.json', server_config(s, c))
    os.chown(directory / 'config.json', 0, grp.getgrnam('xray').gr_gid)
    os.chmod(directory / 'config.json', 0o640)
    authdir = Path('/etc/vless-panel')
    authdir.mkdir(mode=0o750)
    os.chown(authdir, 0, grp.getgrnam('vless-admin').gr_gid)
    password, salt = secrets.token_urlsafe(32), secrets.token_hex(16)
    write(authdir / 'admin.json', dict(username='test-admin', salt=salt, secret=secrets.token_hex(32),
        password_hash=password_hash(password, salt), domain=s['domain'], panel_path=s['panel_path']))
    os.chown(authdir / 'admin.json', 0, grp.getgrnam('vless-admin').gr_gid)
    os.chmod(authdir / 'admin.json', 0o640)
    unit = (base / 'install.sh').read_text().split('cat > "$WORK/xray.service" <<\'UNIT\'\n')[1].split('\nUNIT\n')[0]
    Path('/etc/systemd/system/xray.service').write_text(unit + '\n')
    nginx_user = re.search(r'^\s*user\s+([^\s;]+)', Path('/etc/nginx/nginx.conf').read_text(), re.M)[1]
    nginx_group = run('id', '-gn', nginx_user).stdout.strip()
    for path in (base / 'services').glob('*.service'):
        text = path.read_text().replace('Group=www-data\n', 'Group=' + nginx_group + '\n')
        (Path('/etc/systemd/system') / path.name).write_text(text)
    run('systemctl', 'daemon-reload')
    try:
        run('systemctl', 'start', 'xray', 'vless-admin', 'vless-panel')
        for _ in range(30):
            if Path('/run/vless-panel/http.sock').exists() and Path('/run/vless-admin/control.sock').exists():
                break
            time.sleep(0.2)
        run('systemctl', 'is-active', '--quiet', 'xray', 'vless-admin', 'vless-panel')
        with tempfile.TemporaryDirectory(prefix='vless-service-') as tmp:
            root = Path(tmp)
            key, cert = root / 'key.pem', root / 'cert.pem'
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                '-out', str(cert), '-days', '1', '-subj', '/CN=vpn.example.test')
            port = available_port()
            Path('/etc/nginx/conf.d/vless-smoke.conf').write_text(f'''
server {{
    listen 127.0.0.1:{port} ssl;
    server_name vpn.example.test;
    ssl_certificate {cert};
    ssl_certificate_key {key};
    location / {{
        proxy_pass http://unix:/run/vless-panel/http.sock;
        proxy_set_header Host vpn.example.test;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
''')
            run('nginx', '-t')
            run('systemctl', 'restart', 'nginx')
            cookie = ''
            context = ssl._create_unverified_context()  # Local test-only certificate.
            def request(method, path, data=None):
                nonlocal cookie
                conn = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=60)
                headers = {'Host': s['domain'], 'Cookie': cookie}
                body = None
                if data is not None:
                    body = urlencode(data)
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    headers['Origin'] = 'https://' + s['domain']
                conn.request(method, s['panel_path'] + path, body, headers)
                response = conn.getresponse()
                if response.getheader('Set-Cookie'):
                    cookie = response.getheader('Set-Cookie').split(';', 1)[0]
                payload = response.read()
                status = response.status
                if status in (302, 303):
                    location = response.getheader('Location')
                    assert location.startswith('/') or location.startswith('https://' + s['domain'] + '/'), 'Unsafe redirect scheme'
                conn.close()
                return status, payload
            status, html = request('GET', '/login')
            assert status == 200, status
            csrf = re.search(rb'name="csrf" value="([^"]+)"', html)[1].decode()
            assert request('POST', '/login', dict(csrf=csrf, username='test-admin', password=password))[0] == 303
            status, html = request('GET', '/')
            assert status == 200, status
            csrf = re.search(rb'name="csrf" value="([^"]+)"', html)[1].decode()
            assert request('POST', '/add', dict(csrf=csrf, name='Service test'))[0] == 303
            keys = rpc(dict(action='list'))
            assert len(keys) == 2
            status, png = request('GET', '/key/' + keys[1]['id'] + '/qr.png')
            assert status == 200 and png.startswith(b'\x89PNG')
            assert request('POST', '/key/' + keys[0]['id'] + '/deactivate', dict(csrf=csrf))[0] == 303
            assert not rpc(dict(action='list'))[0]['active']
            assert request('POST', '/key/' + keys[1]['id'] + '/delete', dict(csrf=csrf))[0] == 303
            assert json.loads((directory / 'config.json').read_text())['inbounds'][0]['settings']['clients'] == []
            new_password = secrets.token_urlsafe(32)
            assert request('POST', '/password', dict(csrf=csrf, current_password='wrong',
                           new_password=new_password, confirmation=new_password))[0] == 400
            assert request('POST', '/password', dict(csrf=csrf, current_password=password,
                           new_password=new_password, confirmation=new_password))[0] == 303
            status, html = request('GET', '/login')
            csrf = re.search(rb'name="csrf" value="([^"]+)"', html)[1].decode()
            assert request('POST', '/login', dict(csrf=csrf, username='test-admin', password=password))[0] == 200
            assert request('POST', '/login', dict(csrf=csrf, username='test-admin', password=new_password))[0] == 303
            saved_auth = json.loads((authdir / 'admin.json').read_text())
            assert saved_auth['password_hash'] == password_hash(new_password, saved_auth['salt'])
            assert (authdir / 'admin.json').stat().st_mode & 0o777 == 0o640
            run('systemctl', 'is-active', '--quiet', 'xray', 'vless-admin', 'vless-panel', 'nginx')
            print('PASS: real systemd units, nonroot panel, Unix socket permissions, Nginx HTTPS, login, add, QR, deactivate, delete.')
    except Exception:
        result = subprocess.run(['journalctl', '-u', 'xray', '-u', 'vless-admin', '-u', 'vless-panel', '-n', '100', '--no-pager'], capture_output=True, text=True)
        print(result.stdout, file=sys.stderr)
        raise
    finally:
        subprocess.run(['systemctl', 'stop', 'vless-panel', 'vless-admin', 'xray'], check=False)


if __name__ == '__main__':
    main()
