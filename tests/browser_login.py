"""Real browser regression: native HTML forms must keep a same-origin Origin."""
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import uuid
import io
import hmac
from PIL import Image
import zxingcpp
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from panel import create_app
from panel_setup import password_hash
from probe import available_port
from werkzeug.serving import make_server, WSGIRequestHandler
from playwright.sync_api import sync_playwright, expect
from config import DEFAULTS, client_url


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
    traffic = [1048576]
    def transport(message):
        if message['action'] == 'list':
            return clients
        if message['action'] == 'statistics':
            return {v['id']: dict(upload=traffic[0], download=2097152, online=v['active'],
                                 last_activity=1794470400, sampled=1794470400) for v in clients}
        if message['action'] == 'add':
            key_id = str(uuid.uuid4())
            credentials = dict(uuid=key_id, private_key=secrets.token_urlsafe(32), public_key=secrets.token_urlsafe(32),
                               short_id=secrets.token_hex(8), path='/api/v2/session/' + secrets.token_hex(16))
            clients.append(dict(id=key_id, name=message['name'], active=True,
                                created='2026-11-11', link=client_url(DEFAULTS, credentials, message['name'])))
        elif message['action'] == 'deactivate':
            next(v for v in clients if v['id'] == message['id'])['active'] = False
        elif message['action'] == 'delete':
            clients[:] = [v for v in clients if v['id'] != message['id']]
        elif message['action'] == 'change_password':
            if not hmac.compare_digest(password_hash(message['current_password'], auth['salt']), auth['password_hash']):
                return {'ok': False}
            auth.update(password_hash=password_hash(message['new_password'], auth['salt']), version=secrets.token_hex(32))
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
                            navigations = []
                            page.on('framenavigated', lambda frame: navigations.append(frame.url) if frame == page.main_frame else None)
                            original_url = page.url
                            page.get_by_label('Название устройства').fill('Browser device')
                            page.get_by_role('button', name='Создать ключ', exact=True).click()
                            expect(page.get_by_role('heading', name='Browser device', exact=True)).to_be_visible()
                            expect(page.get_by_role('button', name='Создать ключ', exact=True)).to_be_enabled()
                            assert results[-1] == 200
                            assert 'создан' in page.locator('#operation-status').inner_text()
                            expect(page.locator('#client-count')).to_have_text('1 активных · 1 всего')
                            preview = page.locator('img.qr-preview')
                            expect(preview).to_be_visible()
                            decoded = zxingcpp.read_barcode(np.asarray(Image.open(io.BytesIO(preview.screenshot())).convert('RGB')))
                            assert decoded is not None and decoded.text == clients[0]['link']
                            download = page.get_by_role('link', name='Скачать QR')
                            assert download.is_visible()
                            assert len(clients) == 1
                            expect(page.locator('[data-stat="online"]')).to_have_text('Есть соединения', timeout=15000)
                            expect(page.locator('[data-stat="total"]')).to_have_text('3.00 МиБ')
                            traffic[0] = 2097152
                            expect(page.locator('[data-stat="total"]')).to_have_text('4.00 МиБ', timeout=15000)
                            page.once('dialog', lambda dialog: dialog.accept())
                            page.get_by_role('button', name='Деактивировать', exact=True).click()
                            expect(page.locator('.badge')).to_have_text('Отключён')
                            expect(page.locator('img.qr-preview')).to_have_count(0)
                            expect(page.locator('#client-count')).to_have_text('0 активных · 1 всего')
                            expect(page.get_by_role('button', name='Удалить', exact=True)).to_be_enabled()
                            page.once('dialog', lambda dialog: dialog.accept())
                            page.get_by_role('button', name='Удалить', exact=True).click()
                            expect(page.get_by_role('heading', name='Ключей пока нет')).to_be_visible()
                            expect(page.locator('#client-count')).to_have_text('0 активных · 0 всего')
                            expect(page.get_by_role('button', name='Создать ключ', exact=True)).to_be_enabled()
                            assert page.url == original_url and navigations == []
                            # Event delegation must also work after replacing the list.
                            page.get_by_label('Название устройства').fill('Second device')
                            page.get_by_role('button', name='Создать ключ', exact=True).click()
                            expect(page.get_by_role('heading', name='Second device', exact=True)).to_be_visible()
                            expect(page.get_by_role('button', name='Выйти', exact=True)).to_be_enabled()
                            page.get_by_role('link', name='Сменить пароль', exact=True).click()
                            page.get_by_label('Текущий пароль', exact=True).fill('wrong-password')
                            new_password = secrets.token_urlsafe(32)
                            page.get_by_label('Новый пароль', exact=True).fill(new_password)
                            page.get_by_label('Повтор нового пароля', exact=True).fill(new_password)
                            with page.expect_navigation():
                                page.get_by_role('button', name='Сохранить пароль', exact=True).click()
                            assert page.get_by_role('alert').inner_text() == 'Неверный текущий пароль.'
                            page.get_by_label('Текущий пароль', exact=True).fill(password)
                            page.get_by_label('Новый пароль', exact=True).fill(new_password)
                            page.get_by_label('Повтор нового пароля', exact=True).fill(new_password)
                            with page.expect_navigation():
                                page.get_by_role('button', name='Сохранить пароль', exact=True).click()
                            expect(page.get_by_role('heading', name='Управление VPN')).to_be_visible()
                            page.get_by_label('Логин').fill('browser-test')
                            page.get_by_label('Пароль', exact=True).fill(new_password)
                            with page.expect_navigation():
                                page.get_by_role('button', name='Войти', exact=True).click()
                            expect(page.get_by_role('heading', name='Ключи подключения')).to_be_visible()
                            with page.expect_navigation():
                                page.get_by_role('button', name='Выйти', exact=True).click()
                            assert page.get_by_role('heading', name='Управление VPN').is_visible()
                        context.close()
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
    print('PASS: native login, lost mutation response, live CRUD and statistics without navigation, scan rendered QR thumbnail, logout.')


if __name__ == '__main__':
    main()
