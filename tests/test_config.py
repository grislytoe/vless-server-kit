import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import DEFAULTS, client_config, client_url, new_credentials, nginx_config, server_config, validate

XRAY = os.environ.get("XRAY_TEST_BIN")


class ConfigTests(unittest.TestCase):
    def test_rejects_nginx_injection(self):
        for domain in ("example.com; return 200;", "example.com\n}", "-example.com", "a..com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                validate(dict(DEFAULTS, domain=domain))

    def test_rejects_conflicting_ports_and_ips(self):
        for changes in (dict(fallback_port=443), dict(fallback_port=80),
                        dict(outbound_ip=DEFAULTS["inbound_ip"]), dict(inbound_ip="999.1.1.1")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate(dict(DEFAULTS, **changes))

    @unittest.skipUnless(XRAY, "Set XRAY_TEST_BIN to a real Xray binary")
    def test_real_core_and_credential_reuse(self):
        c = new_credentials(XRAY)
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            settings = work / "settings.json"
            credentials = work / "credentials.json"
            settings.write_text(json.dumps(DEFAULTS))
            credentials.write_text(json.dumps(c))
            before = credentials.read_bytes()
            subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "config.py"),
                "credentials", "--settings", str(settings), "--credentials", str(credentials),
                "--xray", XRAY], check=True)
            self.assertEqual(before, credentials.read_bytes())
            for cfg in (server_config(DEFAULTS, c), client_config(DEFAULTS, c)):
                path = work / "config.json"
                path.write_text(json.dumps(cfg))
                result = subprocess.run([XRAY, "run", "-test", "-config", str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(XRAY, "Set XRAY_TEST_BIN")
    def test_link_roundtrip(self):
        c = new_credentials(XRAY)
        link = urlsplit(client_url(DEFAULTS, c))
        params = parse_qs(link.query)
        self.assertEqual(link.username, c["uuid"])
        self.assertEqual(params["path"], [c["path"]])
        self.assertEqual(params["pbk"], [c["public_key"]])
        self.assertNotIn("extra", params)

    def test_no_tls_required_for_bootstrap(self):
        config = nginx_config(DEFAULTS)
        self.assertNotIn("ssl_certificate", config)
        self.assertIn("/.well-known/acme-challenge/", config)


if __name__ == "__main__":
    unittest.main()
