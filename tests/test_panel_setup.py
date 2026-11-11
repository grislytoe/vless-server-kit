"""Run the actual password setup on a controlling TTY with piped stdin."""
import json
import os
from pathlib import Path
import select
import signal
import sys
import tempfile
import time
import unittest

if os.name == 'posix':
    import pty


@unittest.skipUnless(os.name == 'posix', 'Requires a Linux controlling terminal')
class PasswordSetupTests(unittest.TestCase):
    def test_real_terminal_setup_hashes_password_and_preserves_credentials(self):
        base = Path(__file__).resolve().parents[1]
        password = 'temporary-test-password-123'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'settings.json').write_text(json.dumps(dict(
                domain='vpn.example.test', panel_path='/manage-' + 'a' * 32)))
            script = f'''
import json, os, sys
from pathlib import Path
from unittest import mock
sys.path.insert(0, {str(base)!r})
import panel_setup
root = Path({str(root)!r})
mapping = {{'/etc/vless-panel/admin.json': root / 'admin.json',
           '/var/lib/vless-optimized/settings.json': root / 'settings.json'}}
with mock.patch.object(panel_setup, 'Path', side_effect=lambda value: mapping[value]), \
     mock.patch.object(os, 'geteuid', return_value=1000):
    panel_setup.setup()
    before = (root / 'admin.json').read_bytes()
    auth = json.loads(before)
    assert auth['username'] == 'admin-tty'
    assert auth['password_hash'] == panel_setup.password_hash({password!r}, auth['salt'])
    assert {password!r} not in before.decode()
    panel_setup.setup()
    assert before == (root / 'admin.json').read_bytes()
print('PASSWORD_SETUP_AND_REUSE_OK', flush=True)
'''
            pid, fd = pty.fork()
            if pid == 0:
                read_fd, write_fd = os.pipe()
                os.close(write_fd)
                os.dup2(read_fd, 0)
                os.close(read_fd)
                os.execv(sys.executable, [sys.executable, '-c', script])
            output, sent, status = b'', 0, None
            # Exercise invalid login, excess Backspace at the field boundary,
            # short password, mismatch, then a corrected hidden password.
            prompts = [(b'Panel login ', b'x\n'),
                       (b'Please try again.', b'\x7f\x7fadmin-ttx\x7fy\n'),
                       (b'Panel password (at least 16 characters): ', b'short\n'),
                       (b'Password length must be', password.encode() + b'\n'),
                       (b'Repeat password: ', b'wrong-confirmation\n'),
                       (b'Passwords do not match.', password[:-1].encode() + b'x\x7f' + password[-1:].encode() + b'\n'),
                       (b'Repeat password: ', password.encode() + b'\n')]
            consumed = 0
            deadline = time.monotonic() + 15
            try:
                while time.monotonic() < deadline:
                    if select.select([fd], [], [], 0.2)[0]:
                        try:
                            chunk = os.read(fd, 8192)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output += chunk
                    if sent < len(prompts):
                        found = output.find(prompts[sent][0], consumed)
                        if found >= 0:
                            # Wait for the next complete password prompt before
                            # typing, after getpass has disabled terminal echo.
                            end = found + len(prompts[sent][0])
                            if sent in (1, 3, 5):
                                next_prompt = b'Panel login ' if sent == 1 else b'Panel password (at least 16 characters): '
                                marker = output.find(next_prompt, end)
                                if marker < 0:
                                    continue
                                end = marker + len(next_prompt)
                            os.write(fd, prompts[sent][1])
                            consumed = end
                            sent += 1
                result, status = os.waitpid(pid, os.WNOHANG)
                if not result:
                    os.kill(pid, signal.SIGKILL)
                    _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors='replace'))
                self.assertIn(b'PASSWORD_SETUP_AND_REUSE_OK', output)
                self.assertNotIn(password.encode(), output, 'Terminal echoed the password')
                self.assertEqual(sent, len(prompts))
            finally:
                if status is None:
                    result, _ = os.waitpid(pid, os.WNOHANG)
                    if not result:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
