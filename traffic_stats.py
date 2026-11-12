"""Private aggregate traffic history. No destination or client IP history is stored."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import uuid

API_SOCKET = Path('/run/xray-stats/api.sock')


def query_snapshot(binary='/usr/local/bin/xray', address=None, epoch_reader=None):
    address = address or 'unix://' + str(API_SOCKET)
    epoch_reader = epoch_reader or (lambda: str(API_SOCKET.stat().st_ino) + ':' + str(API_SOCKET.stat().st_ctime_ns))
    epoch = epoch_reader()
    def query(command, *flags):
        result = subprocess.run([str(binary), 'api', command, '--server=' + address,
            '--timeout=2', *flags], check=True, capture_output=True, text=True, timeout=4)
        return json.loads(result.stdout)
    traffic = query('statsquery', '-pattern', 'user>>>')
    online = query('statsonlineiplist', '-all')
    if epoch_reader() != epoch:
        raise RuntimeError('Xray restarted during collection')
    values = {}
    for counter in traffic.get('stat', []):
        parts = counter['name'].split('>>>')
        if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic' or parts[3] not in ('uplink', 'downlink'):
            continue
        identity = str(uuid.UUID(parts[1]))
        value = int(counter.get('value', 0))
        if value < 0:
            raise ValueError('Negative traffic counter')
        values.setdefault(identity, {})[parts[3]] = value
    for user in online.get('users', []):
        identity = str(uuid.UUID(user['email']))
        row = values.setdefault(identity, {})
        row['online'] = len(user.get('ips', []))
        row['last_connection'] = max((int(ip.get('lastSeen', 0)) for ip in user.get('ips', [])), default=0)
    return epoch, values


class TrafficStore:
    def __init__(self, path):
        self.path = Path(path)
        with closing(self.connect()) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS traffic (
                id TEXT PRIMARY KEY, epoch TEXT NOT NULL, raw_up INTEGER NOT NULL,
                raw_down INTEGER NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL,
                last_activity REAL, online INTEGER NOT NULL, sampled REAL NOT NULL)''')
            db.execute('CREATE TABLE IF NOT EXISTS health (id INTEGER PRIMARY KEY CHECK(id=1), ok INTEGER NOT NULL)')
        if os.name == 'posix':
            os.chmod(self.path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=3)
        db.row_factory = sqlite3.Row
        return db

    def collect(self, identities, epoch, values, now=None):
        now = time.time() if now is None else now
        with closing(self.connect()) as db, db:
            for identity in identities:
                old = db.execute('SELECT * FROM traffic WHERE id=?', (identity,)).fetchone()
                row = values.get(identity, {})
                up, down = row.get('uplink', 0), row.get('downlink', 0)
                same = old is not None and old['epoch'] == epoch
                if same and (up < old['raw_up'] or down < old['raw_down']):
                    raise ValueError('Counters decreased without a new Xray generation')
                delta_up = up - old['raw_up'] if same else up
                delta_down = down - old['raw_down'] if same else down
                last = old['last_activity'] if old else None
                candidate = now if delta_up or delta_down else row.get('last_connection', 0)
                if candidate:
                    last = max(last or 0, min(candidate, now))
                db.execute('INSERT OR REPLACE INTO traffic VALUES (?,?,?,?,?,?,?,?,?)',
                    (identity, epoch, up, down, (old['upload'] if old else 0) + delta_up,
                     (old['download'] if old else 0) + delta_down, last, row.get('online', 0), now))
            # Deleted keys do not leave permanent history behind.
            existing = [r[0] for r in db.execute('SELECT id FROM traffic')]
            for identity in set(existing) - set(identities):
                db.execute('DELETE FROM traffic WHERE id=?', (identity,))
            db.execute('INSERT OR REPLACE INTO health VALUES (1,1)')

    def failed(self):
        with closing(self.connect()) as db, db:
            db.execute('INSERT OR REPLACE INTO health VALUES (1,0)')

    def read(self, now=None):
        now = time.time() if now is None else now
        with closing(self.connect()) as db:
            health = db.execute('SELECT ok FROM health WHERE id=1').fetchone()
            return {r['id']: dict(upload=r['upload'], download=r['download'],
                last_activity=r['last_activity'], sampled=r['sampled'],
                online=bool(r['online']) if health and health[0] and 0 <= now-r['sampled'] <= 20 else None)
                for r in db.execute('SELECT * FROM traffic')}
