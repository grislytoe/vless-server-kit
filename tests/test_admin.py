import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from admin import Manager, validate_clients
from config import DEFAULTS, server_config, write


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.credentials = dict(uuid=str(uuid.uuid4()), private_key='A' * 43,
            public_key='B' * 43, short_id='1234567890abcdef', path='/test-path')
        write(self.root / 'settings.json', DEFAULTS)
        write(self.root / 'credentials.json', self.credentials)
        self.config = self.root / 'config.json'
        write(self.config, server_config(DEFAULTS, self.credentials))
        self.calls = []

        def runner(command, **kwargs):
            self.calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        self.manager = Manager(self.root, self.config, runner)
        # Tests run without elevated privileges even in root-owned containers.
        self.manager._install_config = lambda data: write(self.config, data)
        self.manager.initialize()

    def test_add_revoke_delete_and_no_private_key_in_list(self):
        original = self.credentials['uuid']
        self.manager._dispatch(dict(action='add', name='Laptop'))
        clients = self.manager._dispatch(dict(action='list'))
        self.assertEqual(len(clients), 2)
        self.assertNotIn('private_key', json.dumps(clients))
        self.assertTrue(all(c['link'].startswith('vless://') for c in clients))
        (self.root / 'client.txt').write_text('old link')
        self.manager._dispatch(dict(action='deactivate', id=original))
        users = json.loads(self.config.read_text())['inbounds'][0]['settings']['clients']
        self.assertEqual(users, [dict(id=clients[1]['id'])])
        self.assertFalse((self.root / 'client.txt').exists())
        clients = self.manager._dispatch(dict(action='list'))
        self.assertEqual(clients[0]['link'], '')
        self.manager._dispatch(dict(action='delete', id=clients[1]['id']))
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][0]['settings']['clients'], [])
        self.assertGreaterEqual(sum(c == ['systemctl', 'restart', 'xray'] for c in self.calls), 3)

    def test_validation_failure_leaves_files_untouched(self):
        before = self.config.read_bytes()
        clients_before = (self.root / 'clients.json').read_bytes()
        def fail(*args, **kwargs):
            raise subprocess.CalledProcessError(1, args[0])
        self.manager.runner = fail
        with self.assertRaises(subprocess.CalledProcessError):
            self.manager._dispatch(dict(action='add', name='Invalid config'))
        self.assertEqual(before, self.config.read_bytes())
        self.assertEqual(clients_before, (self.root / 'clients.json').read_bytes())
        self.assertFalse((self.root / 'pending.json').exists())

    def test_failed_restart_rolls_back(self):
        before = self.config.read_bytes()
        clients_before = (self.root / 'clients.json').read_bytes()
        def fail_once(command, **kwargs):
            if command == ['systemctl', 'restart', 'xray'] and not self.calls:
                self.calls.append(command)
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0)
        self.manager.runner = fail_once
        with self.assertRaises(subprocess.CalledProcessError):
            self.manager._dispatch(dict(action='add', name='Failed restart'))
        self.assertEqual(before, self.config.read_bytes())
        self.assertEqual(clients_before, (self.root / 'clients.json').read_bytes())
        self.assertFalse((self.root / 'pending.json').exists())

    def test_crash_journal_restores_old_config_and_clients(self):
        old_config = json.loads(self.config.read_text())
        old_clients = self.manager.initialize()
        write(self.root / 'pending.json', dict(config=old_config, clients=old_clients))
        write(self.config, {'broken': True})
        write(self.root / 'clients.json', [])
        self.manager.recover()
        self.assertEqual(json.loads(self.config.read_text()), old_config)
        self.assertEqual(self.manager.initialize(), old_clients)

    def test_rejects_unknown_operations_and_bad_clients(self):
        for request in (dict(action='run', command='anything'), dict(action='add', name=''),
                        dict(action='add', name='a\nb'), dict(action='delete', id='bad')):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.manager._dispatch(request)
        clients = self.manager.initialize()
        with self.assertRaises(ValueError):
            validate_clients(clients + copy.deepcopy(clients))


if __name__ == '__main__':
    unittest.main()
