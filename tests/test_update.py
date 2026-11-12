import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import DEFAULTS, write
from update_guard import capture, verify


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        settings = dict(DEFAULTS, panel_path='/manage-' + 'a' * 32)
        credentials = dict(uuid=str(uuid.uuid4()), private_key='A' * 43,
            public_key='B' * 43, short_id='1234567890abcdef', path='/existing')
        self.account = self.root / 'admin.json'
        write(self.root / 'settings.json', settings)
        write(self.root / 'credentials.json', credentials)
        write(self.root / 'clients.json', [dict(id=credentials['uuid'], name='Revoked', active=False),
            dict(id=str(uuid.uuid4()), name='iPhone', active=True)])
        write(self.account, dict(username='admin', salt='ab' * 16, password_hash='cd' * 32,
            secret='ef' * 32, domain=settings['domain'], panel_path=settings['panel_path']))
        self.before = capture(self.root, self.account)

    def test_existing_and_revoked_clients_survive_additive_metadata(self):
        after = copy.deepcopy(self.before)
        after['settings']['schema_version'] = 2
        verify(self.before, after)
        verify(self.before, capture(self.root, self.account))

    def test_uuid_private_key_password_and_revocation_changes_are_rejected(self):
        for section, key, value in [('credentials', 'uuid', str(uuid.uuid4())),
                ('credentials', 'private_key', 'C' * 43), ('account', 'password_hash', '00'),
                ('settings', 'panel_path', '/changed'), ('settings', 'inbound_ip', '192.0.2.99')]:
            with self.subTest(section=section, key=key):
                after = copy.deepcopy(self.before)
                after[section][key] = value
                with self.assertRaises(ValueError):
                    verify(self.before, after)
        after = copy.deepcopy(self.before)
        after['clients'][0]['active'] = True
        with self.assertRaises(ValueError):
            verify(self.before, after)

    def test_incomplete_installation_is_not_reinitialized(self):
        (self.root / 'credentials.json').unlink()
        with self.assertRaises(FileNotFoundError):
            capture(self.root, self.account)
        self.assertFalse((self.root / 'credentials.json').exists())

    def test_empty_client_list_stays_empty(self):
        write(self.root / 'clients.json', [])
        current = capture(self.root, self.account)
        verify(current, capture(self.root, self.account))
        self.assertEqual(current['clients'], [])

    @unittest.skipUnless(os.environ.get('BASH_TEST_BIN'), 'Requires bash')
    def test_failed_preservation_check_triggers_actual_installer_rollback(self):
        from test_transaction import posix
        base = Path(__file__).resolve().parents[1]
        source = (base / 'install.sh').read_text()
        functions = source[source.index('declare -a RECORDED=()'):source.index('trap cleanup EXIT')]
        before = self.account.read_bytes()
        helper = self.root / 'check.py'
        helper.write_text('import json, sys\nfrom pathlib import Path\n'
            f'sys.path.insert(0, {str(base)!r})\nfrom update_guard import capture, verify\n'
            f'root=Path({str(self.root)!r})\nauth=root/"admin.json"\n'
            'before=capture(root, auth)\nchanged=json.loads(auth.read_text())\n'
            'changed["password_hash"]="unexpected"\nauth.write_text(json.dumps(changed))\n'
            'verify(before, capture(root, auth))\n')
        script = self.root / 'rollback.sh'
        script.write_text('set -Eeuo pipefail\n'
            + f'STATE={shlex.quote(posix(self.root))}\nWORK="$STATE/work.test"\nBACKUP="$STATE/backup"\n'
            + 'MANAGED=true\nsystemctl() { return 0; }\n' + functions
            + '\nmkdir -p "$WORK" "$BACKUP"\ntrap cleanup EXIT\nsnapshot "$STATE/admin.json"\n'
            + shlex.quote(posix(Path(sys.executable))) + ' ' + shlex.quote(posix(helper)) + '\n', newline='\n')
        result = subprocess.run([os.environ['BASH_TEST_BIN'], posix(script)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'protected user data', result.stderr)
        self.assertEqual(self.account.read_bytes(), before)
