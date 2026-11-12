#!/usr/bin/env python3
"""Pure configuration builders. No remote code, shell interpolation or private-key output."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
from urllib.parse import quote, urlencode
import uuid

VERSION = "26.11.9"
# Safe documentation values only. Installation always requires explicit parameters.
DEFAULTS = dict(domain="vpn.example.com", inbound_ip="192.0.2.10",
                outbound_ip="192.0.2.11", port=443, fallback_port=26869)


def validate(settings):
    domain = settings["domain"]
    if len(domain) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", domain
    ):
        raise ValueError("Use a lower-case ASCII DNS name (punycode if needed).")
    for name in ("inbound_ip", "outbound_ip"):
        ipaddress.IPv4Address(settings[name])
    if settings["inbound_ip"] == settings["outbound_ip"]:
        raise ValueError("Inbound and outbound IPs must differ for this deployment.")
    for key in ("port", "fallback_port"):
        if type(settings[key]) is not int or not 1024 <= settings[key] <= 65535:
            if key != "port" or settings[key] != 443:
                raise ValueError("Invalid port.")
    if settings["port"] in (22, 80) or settings["fallback_port"] in (22, 80, settings["port"]):
        raise ValueError("SSH, HTTP, public and fallback ports must not conflict.")
    if settings.get("fingerprint", "firefox") not in ("chrome", "firefox"):
        raise ValueError("Unsupported fingerprint.")
    if "panel_path" in settings and not re.fullmatch(r"/manage-[0-9a-f]{32}", settings["panel_path"]):
        raise ValueError("Invalid panel path.")
    return settings


def validate_credentials(value):
    uuid.UUID(value["uuid"])
    for key in ("private_key", "public_key"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value[key]):
            raise ValueError("Invalid X25519 key.")
        if len(base64.urlsafe_b64decode(value[key] + "=")) != 32:
            raise ValueError("Invalid X25519 key length.")
    if not re.fullmatch(r"[0-9a-f]{16}", value["short_id"]):
        raise ValueError("Invalid REALITY shortId.")
    if not re.fullmatch(r"/[A-Za-z0-9/_-]{1,160}", value["path"]):
        raise ValueError("Invalid XHTTP path.")
    return value


def new_credentials(xray):
    output = subprocess.check_output([str(xray), "x25519"], text=True)
    pairs = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
    pairs = {k.strip().lower().replace(" ", ""): v.strip() for k, v in pairs.items()}
    return validate_credentials(dict(
        uuid=str(uuid.uuid4()), private_key=pairs.get("privatekey", ""),
        public_key=pairs.get("password(publickey)", pairs.get("password", pairs.get("publickey", ""))),
        short_id=secrets.token_hex(8), path="/api/v2/session/" + secrets.token_hex(16)))


def server_config(settings, credentials, clients=None, stats_address='/run/xray-stats/api.sock'):
    s, c = validate(settings), validate_credentials(credentials)
    ids = [c["uuid"]] if clients is None else [str(uuid.UUID(v["id"])) for v in clients if v["active"]]
    return {
        "stats": {},
        "api": {"tag": "stats-api", "listen": stats_address, "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True}}},
        "log": {"access": "none", "loglevel": "warning"},
        "inbounds": [{"tag": "vless-xhttp", "listen": s["inbound_ip"],
            "port": s["port"], "protocol": "vless",
            "settings": {"clients": [{"id": value, "email": value} for value in ids], "decryption": "none"},
            "streamSettings": {"network": "xhttp", "security": "reality",
                "realitySettings": {"show": False, "target": f"127.0.0.1:{s['fallback_port']}",
                    "xver": 1, "serverNames": [s["domain"]],
                    "privateKey": c["private_key"], "shortIds": [c["short_id"]]},
                "xhttpSettings": {"path": c["path"], "mode": "auto"}},
            "sniffing": {"enabled": False}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom",
            "sendThrough": s["outbound_ip"],
            "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}}],
    }


def client_config(settings, credentials, socks_port=10808, address=None):
    s, c = validate(settings), validate_credentials(credentials)
    return {"log": {"access": "none", "loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
            "address": address or s["domain"], "port": s["port"],
            "users": [{"id": c["uuid"], "encryption": "none"}]}]},
            "streamSettings": {"network": "xhttp", "security": "reality",
                "realitySettings": {"serverName": s["domain"], "fingerprint": s.get("fingerprint", "firefox"),
                    "publicKey": c["public_key"], "shortId": c["short_id"]},
                "xhttpSettings": {"path": c["path"], "mode": "auto"}}}]}


def client_url(settings, credentials, name="HAPP-XHTTP"):
    s, c = validate(settings), validate_credentials(credentials)
    params = {"encryption": "none", "security": "reality", "sni": s["domain"],
        "fp": s.get("fingerprint", "firefox"), "pbk": c["public_key"], "sid": c["short_id"],
        "type": "xhttp", "path": c["path"], "mode": "auto"}
    return f"vless://{c['uuid']}@{s['domain']}:{s['port']}?{urlencode(params)}#{quote(name, safe='')}"


def nginx_config(settings, tls=False):
    s = validate(settings)
    domain, inbound, fallback = s["domain"], s["inbound_ip"], s["fallback_port"]
    text = f"""# Managed by vless-optimized. HTTP-01 renewal never takes over port 443.
server {{
    listen {inbound}:80 default_server;
    server_name _;
    return 404;
}}
server {{
    listen {inbound}:80;
    server_name {domain};
    root /var/www/vless-cover;
    location ^~ /.well-known/acme-challenge/ {{ try_files $uri =404; }}
    location / {{ try_files $uri $uri/ =404; }}
}}
"""
    if tls:
        panel = ""
        if s.get("panel_path"):
            p = s["panel_path"]
            panel = f"""
    location = {p} {{ access_log off; return 302 {p}/; }}
    location ^~ {p}/ {{
        access_log off;
        client_max_body_size 8k;
        limit_req zone=vless_panel burst=20 nodelay;
        proxy_pass http://unix:/run/vless-panel/http.sock;
        proxy_set_header Host {domain};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For "";
        proxy_set_header X-Forwarded-SSL "";
        proxy_set_header X-Forwarded-Protocol "";
        proxy_set_header Forwarded "";
        proxy_http_version 1.0;
        proxy_request_buffering on;
        proxy_set_header Connection "";
        proxy_read_timeout 60s;
    }}
"""
            text = "limit_req_zone $binary_remote_addr zone=vless_panel:10m rate=2r/s;\n" + text
        text += f"""server {{
    listen 127.0.0.1:{fallback} ssl http2 proxy_protocol default_server;
    server_name _;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_reject_handshake on;
}}
server {{
    listen 127.0.0.1:{fallback} ssl http2 proxy_protocol;
    server_name {domain};
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_session_cache shared:VLESS:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    root /var/www/vless-cover;
    index index.html;
    {panel}
    location / {{ try_files $uri $uri/ =404; }}
}}
"""
    return text


def write(path, value, private=True):
    path = Path(path)
    data = json.dumps(value, indent=2) + "\n" if not isinstance(value, str) else value
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600 if private else 0o644)
        os.replace(temporary, path)
        if os.name == 'posix':
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["settings", "credentials", "render", "http"])
    parser.add_argument("--settings", required=True)
    parser.add_argument("--credentials")
    parser.add_argument("--output")
    parser.add_argument("--xray")
    parser.add_argument("--domain")
    parser.add_argument("--inbound")
    parser.add_argument("--outbound")
    args = parser.parse_args()
    if args.command == "settings":
        if not all((args.domain, args.inbound, args.outbound)):
            parser.error("settings requires --domain, --inbound and --outbound")
        write(args.settings, validate(dict(DEFAULTS, domain=args.domain, inbound_ip=args.inbound,
              outbound_ip=args.outbound, fingerprint="chrome", panel_path="/manage-" + secrets.token_hex(16))))
        return
    s = validate(json.loads(Path(args.settings).read_text(encoding="utf-8")))
    if args.command == "http":
        write(args.output, nginx_config(s))
        return
    path = Path(args.credentials)
    if args.command == "credentials":
        if path.exists():
            validate_credentials(json.loads(path.read_text(encoding="utf-8")))
        else:
            write(path, new_credentials(args.xray))
        return
    c = validate_credentials(json.loads(path.read_text(encoding="utf-8")))
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    clients_path = Path(args.settings).with_name("clients.json")
    clients = json.loads(clients_path.read_text(encoding="utf-8")) if clients_path.exists() else None
    write(out / "config.json", server_config(s, c, clients))
    write(out / "client.json", client_config(s, c))
    write(out / "client.txt", client_url(s, c) + "\n")
    write(out / "nginx.conf", nginx_config(s, tls=True))


if __name__ == "__main__":
    main()
