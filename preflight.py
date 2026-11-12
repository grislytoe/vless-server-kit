#!/usr/bin/env python3
"""Read-only network preflight, including a source-bound external IPv4 check."""
import argparse
import http.client
import ipaddress
import json
import socket
import subprocess
import sys

from config import DEFAULTS, validate


def check_dns(domain, inbound):
    answers = {r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)}
    if answers != {inbound}:
        raise ValueError(f'DNS A must contain only {inbound}; found {sorted(answers)}')
    try:
        ipv6 = {r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET6)}
    except socket.gaierror as exc:
        if exc.errno not in (socket.EAI_NONAME, socket.EAI_NODATA):
            print(f'WARNING: IPv6 lookup unavailable ({exc}); continuing with verified IPv4.', file=sys.stderr)
        ipv6 = set()
    if ipv6:
        print('WARNING: System resolver returned IPv6 addresses: ' + ', '.join(sorted(ipv6)) +
              '. Continuing with IPv4. This kit does not serve IPv6; a real public AAAA record'
              ' may prevent domain connections or certificate issuance. Remove an incorrect AAAA'
              ' record; local/cache answers may differ from public DNS.', file=sys.stderr)


def check(domain, inbound, outbound):
    s = validate(dict(DEFAULTS, domain=domain, inbound_ip=inbound, outbound_ip=outbound))
    for value in (inbound, outbound):
        if not ipaddress.IPv4Address(value).is_global:
            raise ValueError('Both addresses must be public IPv4 addresses.')
    check_dns(domain, inbound)
    interfaces = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show'], text=True))
    assigned = {a['local'] for iface in interfaces for a in iface.get('addr_info', [])}
    if not {inbound, outbound} <= assigned:
        raise ValueError('Both addresses must be assigned to a server interface.')
    subprocess.run(['ip', '-4', 'route', 'get', '1.1.1.1', 'from', outbound], check=True)
    for host in ('api.ipify.org', 'checkip.amazonaws.com'):
        conn = http.client.HTTPSConnection(host, timeout=12, source_address=(outbound, 0))
        try:
            conn.request('GET', '/')
            response = conn.getresponse()
            actual = str(ipaddress.IPv4Address(response.read(128).decode().strip()))
            if response.status != 200:
                continue
        except (OSError, ValueError, http.client.HTTPException):
            continue
        finally:
            conn.close()
        if actual != s['outbound_ip']:
            raise ValueError(f'Actual outbound IPv4 is {actual}, expected {outbound}. Check provider NAT.')
        print(f'Source-bound external IPv4 confirmed: {actual}')
        return
    raise RuntimeError('Cannot verify the source-bound external IPv4.')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--domain', required=True)
    p.add_argument('--inbound', required=True)
    p.add_argument('--outbound', required=True)
    a = p.parse_args()
    check(a.domain, a.inbound, a.outbound)
