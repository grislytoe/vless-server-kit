#!/usr/bin/env python3
"""Unprivileged admin UI, published only through the local Nginx TLS fallback."""
from collections import OrderedDict, deque
from datetime import timedelta
from functools import wraps
import hmac
import io
import json
from pathlib import Path
import secrets
import socket
import threading
import time
import uuid

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from panel_setup import password_hash


def rpc(message):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(65)
        conn.connect('/run/vless-admin/control.sock')
        conn.sendall(json.dumps(message).encode() + b'\n')
        raw = conn.makefile('rb').readline(2_000_001)
    if len(raw) > 2_000_000:
        raise RuntimeError('Response too large.')
    result = json.loads(raw)
    if 'error' in result:
        raise RuntimeError(result['error'])
    return result['result']


class LoginLimiter:
    def __init__(self):
        self.entries, self.lock = OrderedDict(), threading.Lock()

    def blocked(self, ip):
        now = time.monotonic()
        with self.lock:
            attempts = self.entries.setdefault(ip, deque())
            self.entries.move_to_end(ip)
            while attempts and attempts[0] < now - 900:
                attempts.popleft()
            if len(self.entries) > 10000:
                self.entries.popitem(last=False)
            if len(attempts) >= 5:
                return True
            attempts.append(now)
            return False


def create_app(auth=None, transport=rpc):
    auth = auth or json.loads(Path('/etc/vless-panel/admin.json').read_text())
    app = Flask(__name__, static_url_path=auth['panel_path'] + '/static')
    # Gunicorn accepts only the local Nginx Unix socket. Trust its fixed HTTPS
    # scheme header, keeping host/address headers outside this trust boundary.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=0, x_proto=1, x_host=0, x_port=0, x_prefix=0)
    prefix = auth['panel_path']
    app.config.update(SECRET_KEY=auth['secret'], SESSION_COOKIE_NAME='vless_admin',
        SESSION_COOKIE_PATH=prefix + '/', SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict', PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=False, MAX_CONTENT_LENGTH=8192)
    limiter = LoginLimiter()
    operations, operation_lock = OrderedDict(), threading.Lock()

    def operation_result(identifier):
        with operation_lock:
            value = operations.get(identifier)
            if value is None or value['owner'] != session['csrf']:
                return None
            return dict(status=value['status'], message=value['message'])


    @app.before_request
    def security():
        if request.host != auth['domain']:
            abort(400)
        # Asset requests must not mint a competing session/CSRF cookie.
        if request.endpoint == 'static':
            return
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        if request.method == 'POST':
            if request.headers.get('Origin') not in (None, 'https://' + auth['domain']):
                app.logger.warning('Form rejected: unexpected Origin header')
                return render_template('request_origin.html'), 403
            if not hmac.compare_digest(session['csrf'].encode(), request.form.get('csrf', '').encode()):
                app.logger.warning('Form rejected: missing or expired CSRF session')
                if request.endpoint == 'login':
                    return render_template('login.html', error=(
                        'Сессия формы устарела или браузер не передал cookie. '
                        'Повторите вход в этой форме. Разрешите cookie для домена панели.')), 403
                return render_template('form_expired.html'), 403

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # no-referrer makes native form POSTs send Origin: null in browsers,
        # contradicting our same-origin check. Keep referrers internal only.
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        return response

    def login_required(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if not session.get('authenticated'):
                return redirect(url_for('login'))
            return function(*args, **kwargs)
        return wrapped

    @app.route(prefix + '/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            if limiter.blocked(request.headers.get('X-Real-IP', request.remote_addr)):
                return render_template('login.html', error='Слишком много попыток. Повторите через 15 минут.'), 429
            password = request.form.get('password', '')
            if len(password) > 256:
                abort(400)
            valid_password = hmac.compare_digest(password_hash(password, auth['salt']), auth['password_hash'])
            if valid_password and hmac.compare_digest(request.form.get('username', '').encode(), auth['username'].encode()):
                session.clear()
                session.update(authenticated=True, csrf=secrets.token_urlsafe(32))
                session.permanent = True
                return redirect(url_for('index'), code=303)
            error = 'Неверный логин или пароль.'
        return render_template('login.html', error=error)

    @app.post(prefix + '/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'), code=303)

    @app.get(prefix + '/')
    @login_required
    def index():
        try:
            clients = transport(dict(action='list'))
        except (OSError, RuntimeError):
            return render_template('error.html'), 503
        result = operation_result(request.args.get('operation', ''))
        return render_template('index.html', clients=clients, domain=auth['domain'], operation=result)

    @app.get(prefix + '/operation/<uuid:identifier>')
    @login_required
    def operation_status(identifier):
        result = operation_result(str(identifier))
        if result is None:
            abort(404)
        return jsonify(result)

    @app.post(prefix + '/add')
    @login_required
    def add():
        name = request.form.get('name', '').strip()
        if not 1 <= len(name) <= 80 or any(ord(v) < 32 for v in name):
            abort(400)
        return mutate(dict(action='add', name=name))

    def mutate(message):
        identifier = request.form.get('operation_id')
        if identifier:
            try:
                identifier = str(uuid.UUID(identifier))
            except ValueError:
                abort(400)
            with operation_lock:
                if identifier in operations:
                    abort(409)
                if len(operations) >= 256:
                    completed = next((k for k, v in operations.items() if v['status'] != 'pending'), None)
                    if completed is None:
                        abort(503)
                    operations.pop(completed)
                operations[identifier] = dict(owner=session['csrf'], status='pending', message='Применяем изменения…')
        try:
            transport(message)
            if message['action'] == 'add':
                notice = f'Ключ «{message["name"]}» создан. Ссылка и QR доступны в списке ниже.'
            else:
                notice = 'Изменения применены. VPN-соединения могут переподключиться.'
            status = 'success'
        except (OSError, RuntimeError):
            notice = 'Не удалось подтвердить применение. Проверьте список ключей и журнал vless-admin перед повтором.'
            status = 'error'
        if identifier:
            with operation_lock:
                operations[identifier].update(status=status, message=notice)
            return jsonify(status=status)
        flash(notice)
        return redirect(url_for('index'), code=303)

    @app.post(prefix + '/key/<uuid:key_id>/<action>')
    @login_required
    def update(key_id, action):
        if action not in ('deactivate', 'delete'):
            abort(404)
        return mutate(dict(action=action, id=str(key_id)))

    @app.get(prefix + '/key/<uuid:key_id>/qr.png')
    @login_required
    def qr(key_id):
        import qrcode
        try:
            clients = transport(dict(action='list'))
        except (OSError, RuntimeError):
            abort(503)
        client = next((v for v in clients if v['id'] == str(key_id) and v['active']), None)
        if client is None:
            abort(404)
        output = io.BytesIO()
        preview = request.args.get('preview') == '1'
        code = qrcode.QRCode(box_size=2 if preview else 8, border=4,
                             error_correction=qrcode.constants.ERROR_CORRECT_M)
        code.add_data(client['link'])
        code.make(fit=True)
        code.make_image(fill_color='black', back_color='white').save(output, format='PNG')
        output.seek(0)
        return send_file(output, mimetype='image/png', as_attachment=not preview,
                         download_name=f'happ-{key_id}.png', max_age=0)

    return app
