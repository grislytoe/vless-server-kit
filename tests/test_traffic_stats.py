import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traffic_stats import TrafficStore, query_snapshot


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'traffic.sqlite3'
        self.store = TrafficStore(self.path)
        self.a, self.b = str(uuid.uuid4()), str(uuid.uuid4())

    def test_deltas_persist_without_double_count_and_restart_has_new_baseline(self):
        values = {self.a: dict(uplink=100, downlink=200, online=1)}
        self.store.collect([self.a, self.b], 'process1', values, now=100)
        self.store = TrafficStore(self.path)
        self.store.collect([self.a, self.b], 'process1', values, now=105)
        self.assertEqual(self.store.read(now=105)[self.a]['upload'], 100)
        self.store.collect([self.a, self.b], 'process2', {self.a: dict(uplink=7, downlink=9)}, now=110)
        row = self.store.read(now=110)[self.a]
        self.assertEqual((row['upload'], row['download']), (107, 209))
        self.assertFalse(row['online'])
        self.assertEqual(row['last_activity'], 110)
        self.assertIsNone(self.store.read(now=110)[self.b]['last_activity'])

    def test_unavailable_or_stale_is_unknown_and_history_stays(self):
        self.store.collect([self.a], 'p', {self.a: dict(uplink=12, online=1)}, now=100)
        self.assertIsNone(self.store.read(now=121)[self.a]['online'])
        self.store.failed()
        self.assertIsNone(self.store.read(now=105)[self.a]['online'])
        self.assertEqual(self.store.read(now=105)[self.a]['upload'], 12)

    def test_invalid_decrease_rolls_back_entire_sample_and_deleted_history_is_removed(self):
        self.store.collect([self.a, self.b], 'p', {self.a: dict(uplink=5), self.b: dict(uplink=10)}, now=100)
        with self.assertRaises(ValueError):
            self.store.collect([self.a, self.b], 'p', {self.a: dict(uplink=50), self.b: dict(uplink=1)}, now=101)
        self.assertEqual(self.store.read(now=101)[self.a]['upload'], 5)
        self.store.collect([self.a], 'p', {self.a: dict(uplink=6)}, now=102)
        self.assertNotIn(self.b, self.store.read(now=102))
        if os.name == 'posix':
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_generation_change_during_query_is_rejected(self):
        from unittest.mock import patch
        from subprocess import CompletedProcess
        with patch('traffic_stats.subprocess.run', return_value=CompletedProcess([], 0, stdout='{}')):
            epochs = iter(['old', 'new'])
            with self.assertRaises(RuntimeError):
                query_snapshot(address='127.0.0.1:1', epoch_reader=lambda: next(epochs))
