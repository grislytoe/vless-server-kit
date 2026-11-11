#!/usr/bin/env python3
"""Short-lived loopback SOCKS client; checks the actual tunnel's exit address."""
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import struct
import secrets
import subprocess
import tempfile
import time

from config import client_config, write


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, process, timeout=10):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError("Xray client exited before listening.")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Xray client did not open the local SOCKS port.")


def recv_exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('SOCKS connection closed.')
        data += part
    return data


def udp_probe(port, resolvers=('1.1.1.1', '8.8.8.8'), dns_port=53):
    """Real DNS datagram via SOCKS UDP ASSOCIATE and the encrypted tunnel."""
    with socket.create_connection(('127.0.0.1', port), timeout=10) as control:
        control.sendall(b'\x05\x01\x00')
        if recv_exact(control, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS authentication failed.')
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        head = recv_exact(control, 4)
        if head[:3] != b'\x05\x00\x00' or head[3] != 1:
            raise RuntimeError('SOCKS UDP associate failed.')
        host = socket.inet_ntoa(recv_exact(control, 4))
        relay_port = struct.unpack('!H', recv_exact(control, 2))[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(7)
            for resolver in resolvers:
                txid = secrets.token_bytes(2)
                query = txid + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x07example\x03com\x00\x00\x01\x00\x01'
                packet = b'\x00\x00\x00\x01' + socket.inet_aton(resolver) + struct.pack('!H', dns_port) + query
                udp.sendto(packet, (host if host != '0.0.0.0' else '127.0.0.1', relay_port))
                try:
                    response = udp.recv(4096)
                except socket.timeout:
                    continue
                if response[:4] != b'\x00\x00\x00\x01':
                    continue
                dns = response[10:]
                if (len(dns) >= 12 and dns[:2] == txid and dns[2] & 128 and
                        dns[3] & 15 == 0 and struct.unpack('!H', dns[6:8])[0] > 0):
                    print(f'UDP through tunnel passed: DNS A example.com via {resolver}.')
                    return
    raise RuntimeError('UDP through tunnel failed with both DNS resolvers.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", required=True)
    parser.add_argument("--settings", required=True)
    parser.add_argument("--credentials", required=True)
    args = parser.parse_args()
    s = json.loads(Path(args.settings).read_text())
    c = json.loads(Path(args.credentials).read_text())
    clients_path = Path(args.settings).with_name('clients.json')
    if clients_path.exists():
        active = [v for v in json.loads(clients_path.read_text()) if v['active']]
        if not active:
            print('No active keys: tunnel/UDP probe skipped; create a key and run probe.py again.')
            return
        c['uuid'] = active[0]['id']
    port = available_port()
    with tempfile.TemporaryDirectory(prefix="vless-probe-") as work:
        config = Path(work) / "client.json"
        logpath = Path(work) / "client.log"
        write(config, client_config(s, c, socks_port=port, address=s["inbound_ip"]))
        with logpath.open("w+") as log:
            process = subprocess.Popen([args.xray, "run", "-config", str(config)], stdout=log, stderr=log)
            try:
                wait_port(port, process)
                errors = []
                for url in ("https://api.ipify.org", "https://checkip.amazonaws.com"):
                    result = subprocess.run(["curl", "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{port}",
                        "-4fsS", "--connect-timeout", "10", "--max-time", "25", url],
                        capture_output=True, text=True)
                    if result.returncode:
                        errors.append(f"{url}: curl exit {result.returncode}")
                        continue
                    try:
                        actual = str(ipaddress.IPv4Address(result.stdout.strip()))
                    except ValueError:
                        errors.append(f"{url}: invalid address response")
                        continue
                    if actual != s["outbound_ip"]:
                        raise RuntimeError(f"Tunnel exit {actual} differs from {s['outbound_ip']}.")
                    print(f"VLESS/XHTTP/REALITY probe passed; outgoing IP: {actual}")
                    udp_probe(port)
                    return
                raise RuntimeError("Tunnel probe failed: " + "; ".join(errors))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
