"""Private, durable session revocation and brute-force counters. Stdlib only."""
import hashlib
import secrets
import sqlite3
import threading
import time


class SecurityState:
    def __init__(self, path=':memory:', clock=time.time):
        self.clock, self.lock = clock, threading.RLock()
        self.db = sqlite3.connect(str(path), timeout=5, check_same_thread=False)
        with self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires REAL NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, timestamp REAL NOT NULL)')
            self.db.execute('CREATE INDEX IF NOT EXISTS attempts_time ON attempts(timestamp)')

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def new_session(self):
        token, now = secrets.token_urlsafe(32), self.clock()
        with self.lock, self.db:
            self.db.execute('DELETE FROM sessions WHERE expires <= ?', (now,))
            self.db.execute('INSERT INTO sessions VALUES (?, ?)', (self.digest(token), now + 1800))
        return token

    def valid(self, token):
        if not isinstance(token, str) or len(token) > 128:
            return False
        with self.lock:
            row = self.db.execute('SELECT expires FROM sessions WHERE id = ?', (self.digest(token),)).fetchone()
        return row is not None and row[0] > self.clock()

    def revoke(self, token):
        if isinstance(token, str):
            with self.lock, self.db:
                self.db.execute('DELETE FROM sessions WHERE id = ?', (self.digest(token),))

    def blocked(self, purpose, address):
        now = self.clock()
        key = self.digest(purpose + ':' + str(address))
        with self.lock, self.db:
            self.db.execute('DELETE FROM attempts WHERE timestamp <= ?', (now - 900,))
            count = self.db.execute('SELECT COUNT(*) FROM attempts WHERE key = ?', (key,)).fetchone()[0]
            global_count = self.db.execute('SELECT COUNT(*) FROM attempts WHERE timestamp > ?', (now - 60,)).fetchone()[0]
            if count >= 5 or global_count >= 60:
                return True
            self.db.execute('INSERT INTO attempts VALUES (?, ?)', (key, now))
            return False
