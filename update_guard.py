"""Validate managed identity and enforce preservation across an in-place update."""
import argparse
import json
from pathlib import Path

from config import validate, validate_credentials, write
from admin import validate_clients


def capture(state=Path('/var/lib/vless-optimized'), auth=Path('/etc/vless-panel/admin.json')):
    state, auth = Path(state), Path(auth)
    settings = validate(json.loads((state / 'settings.json').read_text()))
    credentials = validate_credentials(json.loads((state / 'credentials.json').read_text()))
    clients = validate_clients(json.loads((state / 'clients.json').read_text()))
    account = json.loads(auth.read_text())
    required = ('username', 'salt', 'password_hash', 'secret', 'domain', 'panel_path')
    if any(not isinstance(account.get(k), str) or not account[k] for k in required):
        raise ValueError('Incomplete admin credentials; update refused.')
    if any(account[k] != settings.get(k) for k in ('domain', 'panel_path')):
        raise ValueError('Panel identity differs from server settings.')
    return dict(settings=settings, credentials=credentials, clients=clients, account=account)


def verify(before, after):
    # New metadata fields may be added; existing settings and all user data stay exact.
    for key, value in before['settings'].items():
        if after['settings'].get(key) != value:
            raise ValueError('Update changed an existing server setting; rolling back.')
    for key in ('credentials', 'clients', 'account'):
        if before[key] != after[key]:
            raise ValueError('Update changed protected user data; rolling back.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['parameters', 'capture', 'verify'])
    parser.add_argument('--snapshot', type=Path)
    args = parser.parse_args()
    current = capture()
    if args.command == 'parameters':
        print('\n'.join(current['settings'][k] for k in ('domain', 'inbound_ip', 'outbound_ip')))
    elif args.command == 'capture':
        if args.snapshot is None:
            parser.error('--snapshot required')
        write(args.snapshot, current)
    else:
        if args.snapshot is None:
            parser.error('--snapshot required')
        verify(json.loads(args.snapshot.read_text()), current)
        print('Verified: clients, revoked states, VPN identity and panel credentials preserved.')


if __name__ == '__main__':
    main()
