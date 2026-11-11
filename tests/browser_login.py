"""Real browser regression: native HTML forms must keep a same-origin Origin."""
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from panel import create_app
from panel_setup import password_hash
from probe import available_port
from werkzeug.serving import make_server, WSGIRequestHandler
from playwright.sync_api import sync_playwright


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass  # Do not log session paths.


def main():
    port = available_port()
    prefix = '/manage-' + secrets.token_hex(16)
    password, salt = secrets.token_urlsafe(32), secrets.token_hex(16)
    auth = dict(username='browser-test', salt=salt, secret=secrets.token_hex(32),
                password_hash=password_hash(password, salt), domain=f'127.0.0.1:{port}', panel_path=prefix)
    clients = []
    def transport(message):
        if message['action'] == 'list':
            return clients
        if message['action'] == 'add':
            clients.append(dict(id=str(uuid.uuid4()), name=message['name'], active=True,
                                created='2026-11-11', link='vless://test-only@example.com'))
        return {'ok': True}
    app = create_app(auth, transport)
    policies, origins, results = {'legacy': False}, [], []

    @app.after_request
    def observe(response):
        from flask import request
        if request.method == 'POST':
            origins.append(request.headers.get('Origin'))
            results.append(response.status_code)
        return response

    # Wrap the WSGI response so the legacy policy overrides production headers.
    actual = app.wsgi_app
    def wrapped(environ, start_response):
        def headers(status, values, exc_info=None):
            if policies['legacy']:
                values = [(k, 'no-referrer' if k.lower() == 'referrer-policy' else v) for k, v in values]
            # Simulate the front proxy losing the completed mutation response.
            if environ.get('PATH_INFO', '').endswith('/add'):
                status = '502 Bad Gateway'
            return start_response(status, values, exc_info)
        return actual(environ, headers)
    app.wsgi_app = wrapped

    with tempfile.TemporaryDirectory() as tmp:
        cert, key = Path(tmp) / 'cert.pem', Path(tmp) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                        '-out', str(cert), '-days', '1', '-subj', '/CN=127.0.0.1'], check=True, capture_output=True)
        server = make_server('127.0.0.1', port, app, ssl_context=(str(cert), str(key)), request_handler=QuietHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    for legacy in (True, False):
                        policies['legacy'] = legacy
                        context = browser.new_context(ignore_https_errors=True)
                        page = context.new_page()
                        page.goto(f'https://127.0.0.1:{port}{prefix}/login')
                        page.get_by_label('Логин').fill('browser-test')
                        page.get_by_label('Пароль').fill(password)
                        with page.expect_navigation():
                            page.get_by_role('button', name='Войти', exact=True).click()
                        if legacy:
                            assert origins[-1] == 'null' and results[-1] == 403
                            assert page.get_by_role('heading', name='Не удалось подтвердить источник запроса').is_visible()
                        else:
                            assert origins[-1] == f'https://127.0.0.1:{port}' and results[-1] == 303
                            assert page.get_by_role('heading', name='Ключи подключения').is_visible()
                            page.get_by_label('Название устройства').fill('Browser device')
                            with page.expect_navigation():
                                page.get_by_role('button', name='Создать ключ', exact=True).click()
                            assert results[-1] == 200
                            assert page.url.startswith(f'https://127.0.0.1:{port}{prefix}/?operation=')
                            assert page.get_by_role('heading', name='Browser device', exact=True).is_visible()
                            assert 'создан' in page.locator('#operation-status').inner_text()
                            page.reload()
                            assert len(clients) == 1
                            with page.expect_navigation():
                                page.get_by_role('button', name='Выйти', exact=True).click()
                            assert page.get_by_role('heading', name='Управление VPN').is_visible()
                        context.close()
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
    print('PASS: Chromium reproduces Origin:null with no-referrer; same-origin fixes native login, add and logout forms.')


if __name__ == '__main__':
    main()
