"""Exercise the real /dev/tty prompts while stdin is occupied by a pipe."""
import os
from pathlib import Path
import select
import shlex
import signal
import sys
import time
import unittest

if os.name == 'posix':
    import pty


@unittest.skipUnless(os.name == 'posix', 'Requires a real Linux pseudo-terminal')
class InteractiveTests(unittest.TestCase):
    def test_piped_launch_collects_current_server_values_from_tty(self):
        helper = Path(__file__).resolve().parents[1] / 'inputs.sh'
        script = f'''set -euo pipefail
DOMAIN=""; INBOUND=""; OUTBOUND=""
die() {{ exit 7; }}
ip() {{ printf '2: eth0 inet 198.51.100.10/32\n'; }}
source {shlex.quote(str(helper))}
collect_inputs
printf '\nRESULT:%s|%s|%s\n' "$DOMAIN" "$INBOUND" "$OUTBOUND"
'''
        # pty.fork creates a controlling TTY. Bash's stdin is deliberately a pipe,
        # exactly as with a downloaded one-command script.
        pid, fd = pty.fork()
        if pid == 0:
            read, write = os.pipe()
            os.write(write, script.encode())
            os.close(write)
            os.dup2(read, 0)
            os.execv('/bin/bash', ['bash'])
        output, sent, finished = b'', False, False
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(fd, 8192)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                if b'Domain (e.g.' in output and not sent:
                    os.write(fd, b'new-vpn.example.com\n198.51.100.10\n198.51.100.11\n')
                    sent = True
                result, status = os.waitpid(pid, os.WNOHANG)
                if result:
                    finished = True
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors='replace'))
                    break
            self.assertIn(b'RESULT:new-vpn.example.com|198.51.100.10|198.51.100.11', output)
        finally:
            if not finished:
                result, _ = os.waitpid(pid, os.WNOHANG)
                if not result:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
