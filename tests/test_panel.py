import copy
import re
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from panel import create_app
from panel_setup import password_hash


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.prefix = '/manage-' + 'a' * 32
        self.password = 'test-only password for panel'
        self.auth = dict(username='admin', salt='01' * 16, secret='test-only-session-secret',
                         domain='vpn.example.com', panel_path=self.prefix)
        self.auth['password_hash'] = password_hash(self.password, self.auth['salt'])
        self.keys = [dict(id=str(uuid.uuid4()), name='<script>alert(1)</script>', active=True,
                         created='2026-11-11T10:00:00', link='vless://test-only@example.com:443?type=xhttp'),
                     dict(id=str(uuid.uuid4()), name='Inactive', active=False, created='2026-11-11', link='')]
        self.messages = []
        def transport(message):
            self.messages.append(message)
            if message['action'] == 'statistics':
                return {self.keys[0]['id']: dict(upload=123, download=456, online=True,
                                              last_activity=1700000000, sampled=1700000000)}
            return copy.deepcopy(self.keys) if message['action'] == 'list' else {'ok': True}
        self.app = create_app(self.auth, transport)
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_statistics_require_login_and_return_only_aggregates(self):
        self.assertEqual(self.get('/statistics').status_code, 302)
        self.login()
        result = self.get('/statistics')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json[self.keys[0]['id']]['upload'], 123)
        self.assertEqual(result.headers['Cache-Control'], 'no-store')
        self.assertNotIn('link', result.get_data(as_text=True))

    def get(self, path, **kwargs):
        return self.client.get(self.prefix + path, base_url='https://vpn.example.com', **kwargs)

    def post(self, path, data, **kwargs):
        return self.client.post(self.prefix + path, base_url='https://vpn.example.com', data=data, **kwargs)

    def csrf(self):
        with self.client.session_transaction(path=self.prefix + '/', base_url='https://vpn.example.com') as session:
            return session['csrf']

    def login(self):
        self.get('/login')
        return self.post('/login', dict(csrf=self.csrf(), username='admin', password=self.password),
                         headers={'Origin': 'https://vpn.example.com'})

    def test_authentication_csrf_and_cookie_flags(self):
        self.assertEqual(self.get('/').status_code, 302)
        self.assertEqual(self.get(f'/key/{self.keys[0]["id"]}/qr.png').status_code, 302)
        self.assertEqual(self.post('/add', dict(name='No csrf')).status_code, 403)
        self.assertEqual(self.login().status_code, 303)
        response = self.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['Referrer-Policy'], 'same-origin')
        self.assertIn('&lt;script&gt;', response.get_data(as_text=True))
        self.assertNotIn('<script>alert(1)</script>', response.get_data(as_text=True))
        self.assertEqual(self.post('/add', dict(csrf=self.csrf(), name='Wrong origin'),
            headers={'Origin': 'https://evil.example'}).status_code, 403)

    def test_login_sets_secure_cookie_and_rotates_csrf(self):
        self.get('/login')
        before = self.csrf()
        response = self.login()
        for value in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=' + self.prefix):
            self.assertIn(value, response.headers['Set-Cookie'])
        self.assertNotEqual(before, self.csrf())

    def test_add_revoke_delete_and_qr(self):
        self.login()
        key = self.keys[0]['id']
        response = self.get(f'/key/{key}/qr.png')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertIn('attachment', response.headers['Content-Disposition'])
        preview = self.get(f'/key/{key}/qr.png?preview=1')
        self.assertEqual(preview.status_code, 200)
        self.assertIn('inline', preview.headers['Content-Disposition'])
        self.assertTrue(preview.data.startswith(b'\x89PNG'))
        self.assertLess(len(preview.data), len(response.data))
        self.assertEqual(self.get(f'/key/{self.keys[1]["id"]}/qr.png').status_code, 404)
        for path, fields in (('/add', dict(name='ПК')), (f'/key/{key}/deactivate', {}), (f'/key/{key}/delete', {})):
            self.assertEqual(self.post(path, dict(csrf=self.csrf(), **fields)).status_code, 303)
        self.assertEqual([m['action'] for m in self.messages], ['list', 'list', 'list', 'add', 'deactivate', 'delete'])
        self.assertEqual(self.get(f'/key/{key}/delete').status_code, 405)
        self.assertEqual(self.post('/logout', dict(csrf=self.csrf())).status_code, 303)
        self.assertEqual(self.get('/').status_code, 302)

    def test_login_throttles_and_rejects_wrong_host(self):
        self.get('/login')
        for _ in range(5):
            self.assertEqual(self.post('/login', dict(csrf=self.csrf(), username='админ', password='wrong')).status_code, 200)
        self.assertEqual(self.post('/login', dict(csrf=self.csrf(), username='admin', password=self.password)).status_code, 429)
        self.assertEqual(self.client.get(self.prefix + '/login', base_url='https://evil.example').status_code, 400)

    def test_unavailable_broker_and_csrf_unicode(self):
        self.login()
        self.assertEqual(self.post('/add', dict(csrf='тест', name='test')).status_code, 403)
        def fail(message):
            raise OSError('private internal failure')
        app = create_app(self.auth, fail)
        client = app.test_client()
        with client.session_transaction(path=self.prefix + '/', base_url='https://vpn.example.com') as session:
            session.update(authenticated=True, csrf='test', sid=app.extensions['security_state'].new_session())
        response = client.get(self.prefix + '/', base_url='https://vpn.example.com')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('private internal failure', response.get_data(as_text=True))

    def test_stale_login_form_recovers_with_cookie_and_csrf_checks(self):
        self.get('/login')
        old_token = self.csrf()
        # Reopening an old tab after clearing cookies / replacing a session.
        self.client = self.app.test_client()
        response = self.post('/login', dict(csrf=old_token, username='admin', password=self.password))
        self.assertEqual(response.status_code, 403)
        self.assertIn('cookie', response.get_data(as_text=True))
        new_token = re.search(r'name="csrf" value="([^"]+)"', response.get_data(as_text=True))[1]
        self.assertNotEqual(old_token, new_token)
        self.assertEqual(self.post('/login', dict(csrf=new_token, username='admin', password=self.password)).status_code, 303)

    def test_static_assets_do_not_create_sessions(self):
        response = self.get('/static/panel.css')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Set-Cookie', response.headers)
        response.close()

    def test_operation_survives_lost_response_without_duplicate_creation(self):
        self.login()
        identifier = str(uuid.uuid4())
        data = dict(csrf=self.csrf(), name='Laptop', operation_id=identifier)
        self.assertEqual(self.post('/add', data).status_code, 200)
        result = self.get('/operation/' + identifier)
        self.assertEqual(result.json['status'], 'success')
        self.assertIn('Laptop', result.json['message'])
        self.assertEqual(self.post('/add', data).status_code, 409)
        self.assertEqual(sum(m['action'] == 'add' for m in self.messages), 1)
        response = self.get('/?operation=' + identifier)
        self.assertIn('Laptop', response.get_data(as_text=True))

    def test_redirect_keeps_https_behind_proxy(self):
        self.get('/login')
        # Ubuntu 22.04's Werkzeug automatically makes Location absolute.
        original = self.app.response_class.autocorrect_location_header
        self.app.response_class.autocorrect_location_header = True
        try:
            response = self.client.post(self.prefix + '/login', base_url='http://vpn.example.com',
                headers={'X-Forwarded-Proto': 'https'},
                data=dict(csrf=self.csrf(), username='admin', password=self.password))
            self.assertEqual(response.status_code, 303)
            self.assertTrue(response.headers['Location'].startswith('https://vpn.example.com/'))
        finally:
            self.app.response_class.autocorrect_location_header = original

    def test_copied_cookie_cannot_be_replayed_after_logout(self):
        self.login()
        with self.client.session_transaction(path=self.prefix + '/', base_url='https://vpn.example.com') as values:
            stolen = dict(values)
        attacker = self.app.test_client()
        with attacker.session_transaction(path=self.prefix + '/', base_url='https://vpn.example.com') as values:
            values.update(stolen)
        self.assertEqual(attacker.get(self.prefix + '/', base_url='https://vpn.example.com').status_code, 200)
        self.post('/logout', dict(csrf=self.csrf()))
        self.assertEqual(attacker.get(self.prefix + '/', base_url='https://vpn.example.com').status_code, 302)

    def test_plaintext_and_static_traversal_rejected(self):
        self.assertEqual(self.client.get(self.prefix + '/login', base_url='http://vpn.example.com').status_code, 400)
        self.assertEqual(self.get('/static/../panel.py').status_code, 404)

    def test_change_password_form_and_session_revocation(self):
        self.assertEqual(self.get('/password').status_code, 302)
        self.login()
        self.assertIn('Сменить пароль', self.get('/').get_data(as_text=True))
        new = 'new-test-password-456'
        self.assertEqual(self.post('/password', dict(csrf=self.csrf(), current_password=self.password,
                         new_password=new, confirmation='different')).status_code, 400)
        self.assertEqual(self.messages[-1]['action'], 'list')
        old_cookie_client = self.client
        self.client = self.app.test_client()
        self.login()
        result = self.post('/password', dict(csrf=self.csrf(), current_password=self.password,
                                           new_password=new, confirmation=new))
        self.assertEqual(result.status_code, 303)
        self.assertEqual(self.messages[-1]['action'], 'change_password')
        # The root manager persists a fresh version; the next request reads it.
        self.auth.update(version='rotated-version', password_hash=password_hash(new, self.auth['salt']))
        self.assertEqual(old_cookie_client.get(self.prefix + '/', base_url='https://vpn.example.com').status_code, 302)
        self.assertEqual(self.get('/').status_code, 302)
        self.password = new
        self.assertEqual(self.login().status_code, 303)


if __name__ == '__main__':
    unittest.main()
