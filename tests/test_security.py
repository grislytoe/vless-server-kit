import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_state import SecurityState


class DurableSecurityTests(unittest.TestCase):
    def test_sessions_and_attempts_survive_restart_and_expire(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'security.sqlite3'
            now = [10000.0]
            state = SecurityState(path, lambda: now[0])
            token = state.new_session()
            for _ in range(5):
                self.assertFalse(state.blocked('login', '198.51.100.1'))
            state.db.close()
            state = SecurityState(path, lambda: now[0])
            try:
                self.assertTrue(state.valid(token))
                self.assertTrue(state.blocked('login', '198.51.100.1'))
                now[0] += 901
                self.assertFalse(state.blocked('login', '198.51.100.1'))
                now[0] += 900
                self.assertFalse(state.valid(token))
                token = state.new_session()
                state.revoke(token)
                self.assertFalse(state.valid(token))
                self.assertNotIn(token.encode(), path.read_bytes())
            finally:
                state.db.close()

    def test_global_limit_cannot_be_bypassed_by_rotating_addresses(self):
        state = SecurityState(clock=lambda: 10000)
        try:
            for n in range(60):
                self.assertFalse(state.blocked('login', str(n)))
            self.assertTrue(state.blocked('login', 'another-ip'))
        finally:
            state.db.close()


@unittest.skipUnless(os.name == 'posix', 'Linux lock semantics')
class LockSafetyTests(unittest.TestCase):
    def test_root_manager_rejects_symlink_lock_without_touching_target(self):
        from unittest import mock
        from admin import Manager
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target, link = root / 'target', root / 'lock'
            target.write_text('must survive')
            link.symlink_to(target)
            actual_open = os.open
            def redirected(path, flags, mode=0o777):
                return actual_open(link if path == '/run/vless-optimized-lock/install.lock' else path, flags, mode)
            with mock.patch('admin.os.open', side_effect=redirected), self.assertRaises(OSError):
                Manager().dispatch({'action': 'list'})
            self.assertEqual(target.read_text(), 'must survive')
