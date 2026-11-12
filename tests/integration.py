"""Real local Xray -> XHTTP/REALITY -> Xray -> HTTP download/upload test.

Uses a real Nginx fallback. No VPS or public listener; throw-away test credentials.
"""
import argparse
from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import DEFAULTS, client_config, new_credentials, nginx_config, server_config, write
from probe import available_port, wait_port, udp_probe
from traffic_stats import TrafficStore, query_snapshot


PAYLOAD = bytes(range(256)) * 16384  # 4 MiB, exact digest checked in both directions.
SOURCES = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        SOURCES.append(self.client_address[0])
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def do_POST(self):
        SOURCES.append(self.client_address[0])
        value = self.rfile.read(int(self.headers["Content-Length"]))
        data = hashlib.sha256(value).hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            # Expected when revocation deliberately closes existing Xray streams.
            pass


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # A deterministic local DNS answer, passed only through the real tunnel.
        response = data[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + data[12:]
        response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01'
        sock.sendto(response, self.client_address)


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def start(stack, args, log):
    process = subprocess.Popen(args, stdout=log, stderr=log)
    stack.callback(stop, process)
    return process


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--xray", required=True)
    p.add_argument("--nginx", required=True)
    p.add_argument("--openssl", required=True)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="vless-integration-", dir=Path(__file__).resolve().parent) as tmp, ExitStack() as stack:
        root = Path(tmp)
        (root / "logs").mkdir()
        (root / "temp").mkdir()
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=lab.example.test"],
            check=True, capture_output=True)
        s = dict(DEFAULTS, domain="lab.example.test", inbound_ip="127.0.0.1", outbound_ip="127.0.0.2",
                 port=available_port(), fallback_port=available_port())
        c = new_credentials(args.xray)
        other = dict(c, uuid=str(uuid.uuid4()))
        nginx = nginx_config(s, tls=True).replace("listen 127.0.0.1:80", f"listen 127.0.0.1:{available_port()}")
        nginx = nginx.replace(f"/etc/letsencrypt/live/{s['domain']}/fullchain.pem", cert.as_posix())
        nginx = nginx.replace(f"/etc/letsencrypt/live/{s['domain']}/privkey.pem", key.as_posix())
        nginx = nginx.replace("/var/www/vless-cover", root.as_posix())
        nginx = nginx.replace('index index.html;', 'index index.html;\nlocation = /whoami { return 200 "$remote_addr"; }')
        (root / "index.html").write_text("local fallback")
        nginx = ("daemon off;\nmaster_process off;\npid logs/nginx.pid;\nerror_log logs/error.log;\n"
                 "events {}\nhttp {\naccess_log logs/access.log;\n"
                 "client_body_temp_path temp/client;\nproxy_temp_path temp/proxy;\n"
                 "fastcgi_temp_path temp/fastcgi;\nuwsgi_temp_path temp/uwsgi;\nscgi_temp_path temp/scgi;\n"
                 + nginx + "\n}\n")
        write(root / "nginx.conf", nginx)
        prefix = root.as_posix() + "/"
        result = subprocess.run([args.nginx, "-t", "-p", prefix, "-c", "nginx.conf"], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        log = stack.enter_context((root / "process.log").open("w+"))
        try:
            fallback = start(stack, [args.nginx, "-p", prefix, "-c", "nginx.conf"], log)
            wait_port(s["fallback_port"], fallback)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(["h2"])
            with socket.create_connection(("127.0.0.1", s["fallback_port"])) as raw:
                raw.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 12345 443\r\n')
                with context.wrap_socket(raw, server_hostname=s["domain"]) as tls:
                    assert tls.selected_alpn_protocol() == "h2"
                    assert tls.version() == "TLSv1.3"
            try:
                with socket.create_connection(("127.0.0.1", s["fallback_port"])) as raw:
                    raw.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 12345 443\r\n')
                    context.wrap_socket(raw, server_hostname="wrong.example.test")
            except ssl.SSLError:
                pass
            else:
                raise AssertionError("Nginx accepted an unauthorized SNI")

            context.set_alpn_protocols(['http/1.1'])
            with socket.create_connection(('127.0.0.1', s['fallback_port'])) as raw:
                raw.sendall(b'PROXY TCP4 198.51.100.44 127.0.0.1 12345 443\r\n')
                with context.wrap_socket(raw, server_hostname=s['domain']) as tls:
                    tls.sendall(f'GET /whoami HTTP/1.1\r\nHost: {s["domain"]}\r\nConnection: close\r\n\r\n'.encode())
                    response = b''
                    while True:
                        part = tls.recv(4096)
                        if not part:
                            break
                        response += part
                    assert response.endswith(b'198.51.100.44'), response

            http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            stack.callback(http.server_close)
            stack.callback(http.shutdown)
            threading.Thread(target=http.serve_forever, daemon=True).start()
            http_port = http.server_address[1]
            dns = socketserver.ThreadingUDPServer(('127.0.0.1', 0), DNSHandler)
            stack.callback(dns.server_close)
            stack.callback(dns.shutdown)
            threading.Thread(target=dns.serve_forever, daemon=True).start()
            dns_port = dns.server_address[1]
            socks = available_port()
            clients = [dict(id=c['uuid'], active=True), dict(id=other['uuid'], active=True)]
            api_port = available_port()
            server_cfg = server_config(s, c, clients, stats_address=f'127.0.0.1:{api_port}')
            # Test-only: permit this exact loopback target. Production keeps Xray's
            # default private-network protection and has no such override.
            server_cfg["outbounds"][0]["settings"] = {"finalRules": [
                {"action": "allow", "ip": ["127.0.0.1"], "port": http_port},
                {"action": "allow", "ip": ["127.0.0.1"], "port": dns_port}]}
            write(root / "server.json", server_cfg)
            client_cfg = client_config(s, c, socks_port=socks, address=s["inbound_ip"])
            client_cfg['outbounds'][0]['sendThrough'] = '127.0.0.2'
            write(root / "client.json", client_cfg)
            server = start(stack, [args.xray, "run", "-config", str(root / "server.json")], log)
            wait_port(s["port"], server)
            client = start(stack, [args.xray, "run", "-config", str(root / "client.json")], log)
            wait_port(socks, client)
            curl = ["curl", "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{socks}",
                    "-fsS", "--connect-timeout", "5", "--max-time", "15"]
            url = f"http://127.0.0.1:{http_port}/data"
            download = subprocess.run(curl + [url], capture_output=True, check=True).stdout
            assert hashlib.sha256(download).digest() == hashlib.sha256(PAYLOAD).digest()
            upload = subprocess.run(curl + ["--data-binary", "@-", url], input=PAYLOAD,
                                    capture_output=True, check=True).stdout
            assert upload.decode() == hashlib.sha256(PAYLOAD).hexdigest()
            # A second connection exercises reuse/reconnect without touching credentials.
            again = subprocess.run(curl + [f"http://localhost:{http_port}/data"], capture_output=True, check=True).stdout
            assert again == PAYLOAD
            assert SOURCES and set(SOURCES) == {"127.0.0.2"}, SOURCES
            def sample():
                return query_snapshot(args.xray, address=f'127.0.0.1:{api_port}', epoch_reader=lambda: str(server.pid))
            store = TrafficStore(root / 'traffic.sqlite3')
            epoch, values = sample()
            store.collect([c['uuid'], other['uuid']], epoch, values)
            initial = store.read()[c['uuid']]
            assert initial['upload'] >= len(PAYLOAD) and initial['download'] >= 2 * len(PAYLOAD), initial
            assert other['uuid'] not in values, 'Traffic was attributed to an unused key'
            held = start(stack, curl + ['--limit-rate', '64k', '--max-time', '4', url], log)
            for _ in range(10):
                time.sleep(0.1)
                _, online_values = sample()
                if online_values.get(c['uuid'], {}).get('online'):
                    break
            assert online_values[c['uuid']]['online'] > 0
            stop(held)
            udp_probe(socks, resolvers=('127.0.0.1',), dns_port=dns_port)
            private = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            stack.callback(private.server_close)
            stack.callback(private.shutdown)
            threading.Thread(target=private.serve_forever, daemon=True).start()
            private_port = private.server_address[1]
            # A reachable private service outside the precise test exceptions
            # must stay inaccessible through VLESS, including DNS resolution.
            import urllib.request
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    f'http://127.0.0.1:{private_port}/data', timeout=5) as direct:
                assert direct.read() == PAYLOAD
            for target in ('127.0.0.1', 'localhost'):
                blocked = subprocess.run(curl + ['--max-time', '4',
                    f'http://{target}:{private_port}/data'], capture_output=True)
                assert blocked.returncode != 0, 'Tunnel reached a private service'
            # Add a second real client, then revoke it by replacing/restarting server config.
            other_port = available_port()
            write(root / 'other.json', client_config(s, other, socks_port=other_port, address=s['inbound_ip']))
            other_process = start(stack, [args.xray, 'run', '-config', str(root / 'other.json')], log)
            wait_port(other_port, other_process)
            other_curl = [v.replace(str(socks), str(other_port)) for v in curl]
            assert subprocess.run(other_curl + [url], capture_output=True, check=True).stdout == PAYLOAD
            epoch, values = sample()
            store.collect([c['uuid'], other['uuid']], epoch, values)
            before_restart = store.read()
            assert before_restart[other['uuid']]['download'] >= len(PAYLOAD)
            stop(server)
            server_cfg['inbounds'][0]['settings']['clients'] = [dict(id=c['uuid'], email=c['uuid'])]
            write(root / 'server.json', server_cfg)
            server = start(stack, [args.xray, 'run', '-config', str(root / 'server.json')], log)
            wait_port(s['port'], server)
            denied = subprocess.run(other_curl + ['--max-time', '4', url], capture_output=True)
            assert denied.returncode != 0, 'Revoked client still connects'
            assert subprocess.run(curl + [url], capture_output=True, check=True).stdout == PAYLOAD
            epoch, values = sample()
            store = TrafficStore(root / 'traffic.sqlite3')
            store.collect([c['uuid'], other['uuid']], epoch, values)
            after_restart = store.read()
            assert after_restart[c['uuid']]['download'] >= before_restart[c['uuid']]['download'] + len(PAYLOAD)
            assert after_restart[other['uuid']]['download'] == before_restart[other['uuid']]['download']
            assert after_restart[other['uuid']]['online'] is False
            print("PASS: real Nginx config, TLS1.3/H2, wrong SNI rejection, real XHTTP/REALITY,")
            print("4 MiB download + upload, UDP, private destination denial, two clients, revocation rejected, remaining client works, outbound source IP.")
            print('PASS: per-key traffic, online detection, durable counters across Xray restart and revoked-key history.')
        except Exception:
            log.flush()
            print((root / "process.log").read_text(errors="replace"), file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
