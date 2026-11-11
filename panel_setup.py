#!/usr/bin/env python3
"""Run from a TTY as root. Passwords never enter argv, shell history or logs."""
import argparse
import getpass
import hashlib
import os
from pathlib import Path
import re
import secrets
import tempfile

from config import write
import json


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32).hex()


def write_auth(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='admin-', dir=path.parent)
    os.close(fd)
    staged = Path(temporary)
    try:
        write(staged, value)
        if os.name == 'posix' and os.geteuid() == 0:
            import grp
            os.chown(staged, 0, grp.getgrnam('vless-admin').gr_gid)
            os.chmod(staged, 0o640)
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)


def read_credentials():
    # A TTY is not seekable. Text mode r+ creates a BufferedRandom stream,
    # which requires seeking; separate read/write streams work with terminals.
    with open('/dev/tty', 'r', encoding='utf-8') as tty_in, \
            open('/dev/tty', 'w', encoding='utf-8') as tty_out:
        # Readline edits only the current input, with arrows/Home/Backspace.
        import readline  # noqa: F401 -- enables the standard input line editor
        saved_in, saved_out = os.dup(0), os.dup(1)
        try:
            os.dup2(tty_in.fileno(), 0)
            os.dup2(tty_out.fileno(), 1)
            while True:
                username = input('Panel login (3–40 letters/digits/_/-): ').strip()
                if re.fullmatch(r'[A-Za-z0-9_-]{3,40}', username):
                    break
                print('Invalid login: use 3–40 letters/digits/_/-. Please try again.')
        finally:
            os.dup2(saved_in, 0)
            os.dup2(saved_out, 1)
            os.close(saved_in)
            os.close(saved_out)
        while True:
            password = getpass.getpass('Panel password (at least 16 characters): ', stream=tty_out)
            if not 16 <= len(password) <= 256:
                tty_out.write('Password length must be 16–256 characters. Please try again.\n')
                tty_out.flush()
                continue
            confirmation = getpass.getpass('Repeat password: ', stream=tty_out)
            if password == confirmation:
                break
            tty_out.write('Passwords do not match. Enter the password twice again.\n')
            tty_out.flush()
    return username, password


def setup(reset=False):
    path = Path('/etc/vless-panel/admin.json')
    if path.exists() and not reset:
        saved = json.loads(path.read_text())
        settings = json.loads(Path('/var/lib/vless-optimized/settings.json').read_text())
        if any(saved[key] != settings[key] for key in ('domain', 'panel_path')):
            raise SystemExit('Panel settings differ; explicit migration is required.')
        return
    username, password = read_credentials()
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
