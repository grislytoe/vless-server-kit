"""Inject a failure into the installer's actual snapshot/rollback functions."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

BASH = os.environ.get("BASH_TEST_BIN")


def posix(path):
    value = path.resolve().as_posix()
    if os.name == "nt":
        return "/" + value[0].lower() + value[2:]
    return value


class TransactionTests(unittest.TestCase):
    @unittest.skipUnless(BASH, "Set BASH_TEST_BIN")
    def test_os_release_does_not_override_xray_version(self):
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        header = source[:source.index('for arg in "$@"; do')]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "os-release").write_text('VERSION="22.04.5 LTS (Jammy Jellyfish)"\n')
            script = root / "test.sh"
            script.write_text(header + '\nsource "$(dirname "$0")/os-release"\nprintf "%s" "$XRAY_VERSION"\n', newline="\n")
            result = subprocess.run([BASH, posix(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "26.11.9")

    @unittest.skipUnless(BASH, "Set BASH_TEST_BIN")
    def test_failure_restores_old_file_and_removes_new_file(self):
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        functions = source[source.index("declare -a RECORDED=()"):source.index("trap cleanup EXIT")]
        with tempfile.TemporaryDirectory(prefix="tx-", dir=Path(__file__).resolve().parents[2]) as tmp:
            root = Path(tmp)
            old = root / "old"
            new = root / "new"
            old.write_text("working config")
            script = f"""set -Eeuo pipefail
STATE={shlex.quote(posix(root))}
WORK="$STATE/work.test"
BACKUP="$STATE/backup"
MANAGED=true
systemctl() {{ return 0; }}
{functions}
mkdir -p "$WORK" "$BACKUP"
trap cleanup EXIT
snapshot "$STATE/old"
snapshot "$STATE/new"
printf broken > "$STATE/old"
printf temporary > "$STATE/new"
exit 23
"""
            result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
            self.assertEqual(old.read_text(), "working config")
            self.assertFalse(new.exists())
            self.assertFalse((root / "work.test").exists())


if __name__ == "__main__":
    unittest.main()
