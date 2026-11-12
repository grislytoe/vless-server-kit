import contextlib
import io
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from preflight import check_dns


class DNSPreflightTests(unittest.TestCase):
    def resolve(self, ipv4, ipv6):
        def lookup(domain, port, family):
            values = ipv4 if family == socket.AF_INET else ipv6
            if isinstance(values, Exception):
                raise values
            return [(family, socket.SOCK_STREAM, 6, '', (value, 0)) for value in values]
        return lookup

    def test_ipv6_warns_with_addresses_but_does_not_block_valid_ipv4(self):
        output = io.StringIO()
        with patch('preflight.socket.getaddrinfo', side_effect=self.resolve(['192.0.2.10'], ['2001:db8::10'])), contextlib.redirect_stderr(output):
            check_dns('vpn.example.com', '192.0.2.10')
        self.assertIn('2001:db8::10', output.getvalue())
        self.assertIn('WARNING', output.getvalue())

    def test_missing_aaaa_is_normal_and_transient_ipv6_failure_is_advisory(self):
        for code in (socket.EAI_NONAME, socket.EAI_AGAIN):
            output = io.StringIO()
            with patch('preflight.socket.getaddrinfo', side_effect=self.resolve(['192.0.2.10'], socket.gaierror(code, 'test DNS answer'))), contextlib.redirect_stderr(output):
                check_dns('vpn.example.com', '192.0.2.10')
            self.assertEqual(bool(output.getvalue()), code == socket.EAI_AGAIN)

    def test_wrong_or_multiple_a_records_still_stop_installation(self):
        for addresses in (['192.0.2.11'], ['192.0.2.10', '192.0.2.11'], []):
            with patch('preflight.socket.getaddrinfo', side_effect=self.resolve(addresses, [])), self.assertRaises(ValueError):
                check_dns('vpn.example.com', '192.0.2.10')
