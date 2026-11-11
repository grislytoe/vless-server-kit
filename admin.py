#!/usr/bin/env python3
"""Root-only state manager. RPC is local, peer-UID checked and has a fixed vocabulary."""
import argparse
import copy
import json
import os
import hmac
import secrets
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone

if os.name == 'posix':
    import fcntl
    import grp
    import pwd

from config import client_url, server_config, validate, validate_credentials, write
from panel_setup import password_hash, write_auth

STATE = Path('/var/lib/vless-optimized')
CONFIG = Path('/usr/local/etc/xray/config.json')
SOCKET = '/run/vless-admin/control.sock'


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def validate_clients(clients):
    if not isinstance(clients, list) or len(clients) > 500:
        raise ValueError('Maximum 500 keys, including inactive keys.')
    seen = set()
    for c in clients:
        value = str(uuid.UUID(c['id']))
        if value != c['id'] or value in seen or type(c['active']) is not bool:
            raise ValueError('Invalid or duplicate client.')
        seen.add(value)
        if not isinstance(c['name'], str) or not 1 <= len(c['name']) <= 80 or any(ord(v) < 32 for v in c['name']):
            raise ValueError('Name must contain 1–80 printable characters.')
    return clients


class Manager:
    def __init__(self, state=STATE, config=CONFIG, runner=subprocess.run, auth_path='/etc/vless-panel/admin.json'):
        self.state, self.config, self.runner = Path(state), Path(config), runner
        self.auth_path = Path(auth_path)

    def initialize(self):
        target = self.state / 'clients.json'
        if not target.exists():
            c = validate_credentials(load(self.state / 'credentials.json'))
            write(target, [dict(id=c['uuid'], name='Initial key', active=True,
                                created=datetime.now(timezone.utc).isoformat())])
        return validate_clients(load(target))

    def _install_config(self, data):
        write(self.config, data)
        if os.name == 'posix' and os.geteuid() == 0:
            os.chown(self.config, 0, grp.getgrnam('xray').gr_gid)
            os.chmod(self.config, 0o640)

    def apply(self, clients):
        """A durable journal recovers crashes between config and state replacement."""
        validate_clients(clients)
        settings = validate(load(self.state / 'settings.json'))
        credentials = validate_credentials(load(self.state / 'credentials.json'))
        new_config = server_config(settings, credentials, clients)
        with tempfile.TemporaryDirectory(prefix='apply-', dir=self.state) as tmp:
            staged = Path(tmp) / 'config.json'
            write(staged, new_config)
            self.runner(['/usr/local/bin/xray', 'run', '-test', '-config', str(staged)],
                        check=True, capture_output=True, timeout=20)
        transaction = self.state / 'pending.json'
        write(transaction, dict(config=load(self.config), clients=self.initialize()))
        try:
            self._install_config(new_config)
            # Restart deliberately closes existing streams, so revocation is immediate.
            self.runner(['systemctl', 'restart', 'xray'], check=True, capture_output=True, timeout=30)
            self.runner(['systemctl', 'is-active', '--quiet', 'xray'], check=True, timeout=10)
            write(self.state / 'clients.json', clients)
            transaction.unlink()
        except Exception:
            self.recover()
            raise

    def recover(self):
        transaction = self.state / 'pending.json'
        if transaction.exists():
            old = load(transaction)
            self._install_config(old['config'])
            write(self.state / 'clients.json', validate_clients(old['clients']))
            self.runner(['systemctl', 'restart', 'xray'], check=True, capture_output=True, timeout=30)
            transaction.unlink()

    def dispatch(self, request):
        fd = os.open('/run/vless-optimized-lock/install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('An installation or another operation is running.')
            return self._dispatch(request)

    def _dispatch(self, request):
        if request.get('action') == 'change_password':
            current, password = request.get('current_password'), request.get('new_password')
            if not isinstance(current, str) or not isinstance(password, str) or not 16 <= len(password) <= 256 or len(current) > 256:
                return dict(ok=False, error='invalid_password')
            auth = load(self.auth_path)
            if not hmac.compare_digest(password_hash(current, auth['salt']), auth['password_hash']):
                return dict(ok=False, error='wrong_password')
            salt = secrets.token_hex(16)
            auth.update(salt=salt, password_hash=password_hash(password, salt), version=secrets.token_hex(32))
            write_auth(self.auth_path, auth)
            return dict(ok=True)
        self.recover()
        clients = self.initialize()
        action = request.get('action')
        if action == 'list':
            s, c = load(self.state / 'settings.json'), load(self.state / 'credentials.json')
            return [dict(v, link=client_url(s, dict(c, uuid=v['id']), v['name']) if v['active'] else '')
                    for v in clients]
        updated = copy.deepcopy(clients)
        if action == 'add':
            updated.append(dict(id=str(uuid.uuid4()), name=request.get('name', '').strip(), active=True,
                                created=datetime.now(timezone.utc).isoformat()))
        elif action in ('deactivate', 'delete'):
            value = str(uuid.UUID(request['id']))
            target = next((v for v in updated if v['id'] == value), None)
            if target is None:
                raise ValueError('Key not found.')
            if action == 'delete':
                updated.remove(target)
            else:
                target['active'] = False
        else:
            raise ValueError('Unknown action.')
        self.apply(updated)
        # Never leave an exported initial key appearing usable after revocation.
        initial = load(self.state / 'credentials.json')['uuid']
        if not any(v['id'] == initial and v['active'] for v in updated):
            for name in ('client.txt', 'client.json', 'client-qr.png'):
                (self.state / name).unlink(missing_ok=True)
        return {'ok': True}


def serve():
    expected_uid = pwd.getpwnam('vless-panel').pw_uid
    manager = Manager()
    manager.recover()
    manager.initialize()
    Path(SOCKET).unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(SOCKET)
        os.chmod(SOCKET, 0o660)
        listener.listen(16)
        while True:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5)
                _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid not in (0, expected_uid):
                    continue
                try:
                    raw = conn.makefile('rb').readline(8193)
                    if len(raw) > 8192 or not raw.endswith(b'\n'):
                        raise ValueError('Request too large.')
                    response = dict(result=manager.dispatch(json.loads(raw)))
                except (ValueError, KeyError, TypeError):
                    response = dict(error='Invalid request or key.')
                except Exception:
                    # Details belong in root's journal, never in public HTTP responses.
                    # Do not include request data / credentials in exception logs.
                    print('Local manager operation failed.', flush=True)
                    response = dict(error='Apply failed; inspect journalctl -u vless-admin.')
                try:
                    conn.sendall(json.dumps(response).encode() + b'\n')
                except OSError:
                    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init', 'serve', 'recover'])
    command = parser.parse_args().command
    if command == 'serve':
        serve()
    elif command == 'recover':
        Manager().recover()
    else:
        Manager().initialize()
