import logging
import os
import sqlite3
import tempfile
import threading
import unittest
import uuid
from contextlib import closing
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from fake_client import FakeClient

from cksum import cksum_bytes
from client_store import ClientStore, FileRecord, NameTakenError, StoreError
from database import Database, DatabaseError
from server import Server, open_database

HOST = "127.0.0.1"


def setUpModule():
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


class TempDbTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "defensive.db"
        self.databases = []

    def tearDown(self):
        for db in self.databases:
            db.close()
        self.tmp.cleanup()

    def open(self):
        db = Database(self.path)
        self.databases.append(db)
        return db

    def columns(self, table):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [row[1] for row in rows]


class SchemaTest(TempDbTest):
    def test_tables_and_columns(self):
        self.open()
        self.assertEqual(
            self.columns("clients"),
            ["ID", "Name", "PublicKey", "LastSeen", "AESKey"],
        )
        self.assertEqual(
            self.columns("files"), ["ID", "FileName", "PathName", "Verified"]
        )

    def test_opening_twice_keeps_data(self):
        ClientStore(self.open()).register("keep-me")
        self.assertIsNotNone(ClientStore(self.open()).find_by_name("keep-me"))

    def test_not_a_database(self):
        self.path.write_bytes(b"this is not sqlite" * 100)
        with self.assertRaises(DatabaseError):
            Database(self.path)
        self.assertIsNone(open_database(self.path))


class PersistenceTest(TempDbTest):
    def test_everything_survives_a_restart(self):
        store = ClientStore(self.open())
        rec = store.register("Ayala")
        store.set_public_key(rec.client_id, b"P" * 160)
        store.set_aes_key(rec.client_id, b"A" * 32)
        store.touch(rec.client_id)
        store.save_file(FileRecord(rec.client_id, "a.bin", "rf/x/a.bin"))
        store.save_file(FileRecord(rec.client_id, "b.bin", "rf/x/b.bin"))
        store.set_verified(rec.client_id, "a.bin", True)
        store.remove_file(rec.client_id, "b.bin")

        reloaded = ClientStore(self.open())
        client = reloaded.get(rec.client_id)
        self.assertEqual(client.name, "Ayala")
        self.assertEqual(client.public_key, b"P" * 160)
        self.assertEqual(client.aes_key, b"A" * 32)
        self.assertTrue(reloaded.get_file(rec.client_id, "a.bin").verified)
        self.assertEqual(
            reloaded.get_file(rec.client_id, "a.bin").path, "rf/x/a.bin"
        )
        self.assertIsNone(reloaded.get_file(rec.client_id, "b.bin"))
        self.assertEqual(reloaded.counts(), (1, 1))

    def test_sql_injection_is_stored_as_plain_text(self):
        names = [
            "x'); DROP TABLE clients; --",
            "' OR '1'='1",
            'a"; DELETE FROM files; --',
        ]
        store = ClientStore(self.open())
        for name in names:
            rec = store.register(name)
            store.save_file(FileRecord(rec.client_id, name, "rf/x"))
        reloaded = ClientStore(self.open())
        self.assertEqual(reloaded.counts(), (3, 3))
        for name in names:
            self.assertIsNotNone(reloaded.find_by_name(name))
        self.assertEqual(
            self.columns("clients"),
            ["ID", "Name", "PublicKey", "LastSeen", "AESKey"],
        )

    def test_name_still_taken_after_restart(self):
        ClientStore(self.open()).register("taken")
        with self.assertRaises(NameTakenError):
            ClientStore(self.open()).register("taken")

    def test_last_seen_is_updated(self):
        store = ClientStore(self.open())
        rec = store.register("seen")
        with closing(sqlite3.connect(self.path)) as conn, conn:
            before = conn.execute("SELECT LastSeen FROM clients").fetchone()[0]
        store.touch(rec.client_id)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            after = conn.execute("SELECT LastSeen FROM clients").fetchone()[0]
        self.assertGreaterEqual(after, before)

    def test_bad_rows_are_skipped(self):
        self.open()
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("PRAGMA ignore_check_constraints = ON")
            conn.execute(
                "INSERT INTO clients VALUES (?, ?, NULL, 'x', NULL)",
                (b"short", "bad-id"),
            )
            conn.execute(
                "INSERT INTO clients VALUES (?, ?, NULL, 'x', NULL)",
                (uuid.uuid4().bytes, ""),
            )
            conn.execute(
                "INSERT INTO clients VALUES (?, ?, NULL, 'not a date', NULL)",
                (uuid.uuid4().bytes, "good"),
            )
        store = ClientStore(self.open())
        self.assertEqual(store.counts(), (1, 0))
        self.assertIsNotNone(store.find_by_name("good"))

    def test_write_failure_leaves_memory_unchanged(self):
        db = self.open()
        store = ClientStore(db)
        rec = store.register("before")
        db.close()
        with self.assertRaises(StoreError):
            store.register("after")
        self.assertIsNone(store.find_by_name("after"))
        with self.assertRaises(StoreError):
            store.set_aes_key(rec.client_id, b"B" * 32)
        self.assertIsNone(store.get(rec.client_id).aes_key)
        store.touch(rec.client_id)

    def test_without_database_nothing_is_written(self):
        store = ClientStore()
        store.register("memory-only")
        self.assertFalse(store.persistent)
        self.assertFalse(self.path.exists())


class RestartEndToEndTest(TempDbTest):
    def start_server(self):
        srv = Server(
            0, Path(self.tmp.name) / "received_files", database=self.open()
        )
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.assertTrue(srv.ready.wait(5))
        return srv

    def test_client_reconnects_after_server_restart(self):
        rsa = RSA.generate(1024, e=17)
        first = self.start_server()
        with FakeClient(HOST, first.port) as c:
            aes_key = c.setup("survivor", rsa)
            self.assertEqual(c.send_file("f.bin", b"before", aes_key)[0], 1603)
            self.assertEqual(c.crc_ok("f.bin")[0], 1604)
            client_id = c.client_id

        second = self.start_server()
        with FakeClient(HOST, second.port) as c:
            c.client_id = client_id
            code, payload = c.reconnect("survivor")
            self.assertEqual(code, 1605)
            new_key = PKCS1_OAEP.new(rsa).decrypt(payload[16:])
            data = os.urandom(5000)
            code, info = c.send_file("g.bin", data, new_key)
            self.assertEqual((code, info[3]), (1603, cksum_bytes(data)))

        with closing(sqlite3.connect(self.path)) as conn, conn:
            rows = conn.execute(
                "SELECT FileName, Verified FROM files ORDER BY FileName"
            ).fetchall()
        self.assertEqual(rows, [("f.bin", 1), ("g.bin", 0)])


if __name__ == "__main__":
    unittest.main()
