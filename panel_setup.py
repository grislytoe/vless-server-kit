#!/usr/bin/env python3
"""Run from a TTY as root. Passwords never enter argv, shell history or logs."""
import argparse
import getpass
import hashlib
import os
from pathlib import Path
import re
import secrets

from config import write
import json


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32).hex()


def setup(reset=False):
    path = Path('/etc/vless-panel/admin.json')
    if path.exists() and not reset:
        saved = json.loads(path.read_text())
        settings = json.loads(Path('/var/lib/vless-optimized/settings.json').read_text())
        if any(saved[key] != settings[key] for key in ('domain', 'panel_path')):
            raise SystemExit('Panel settings differ; explicit migration is required.')
        return
    with open('/dev/tty', 'r+') as tty:
        tty.write('Panel login (3–40 letters/digits/_/-): ')
        tty.flush()
        username = tty.readline().strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{3,40}', username):
            raise SystemExit('Invalid login.')
        password = getpass.getpass('Panel password (at least 16 characters): ', stream=tty)
        confirmation = getpass.getpass('Repeat password: ', stream=tty)
    if len(password) < 16 or len(password) > 256 or password != confirmation:
        raise SystemExit('Passwords must match and contain 16–256 characters.')
    salt = secrets.token_hex(16)
    s = json.loads(Path('/var/lib/vless-optimized/settings.json').read_text())
    write(path, dict(username=username, salt=salt, password_hash=password_hash(password, salt),
                     secret=secrets.token_hex(32), domain=s['domain'], panel_path=s['panel_path']))
    if os.geteuid() == 0:
        import grp
        os.chown(path, 0, grp.getgrnam('vless-admin').gr_gid)
        os.chmod(path, 0o640)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--reset', action='store_true')
    setup(parser.parse_args().reset)
