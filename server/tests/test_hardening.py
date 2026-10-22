import logging
import os
import socket
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from fake_client import FakeClient, name_field

import session as session_module
from cksum import cksum_bytes
from client_store import ClientStore, StoreFullError
from server import Server

HOST = "127.0.0.1"


def setUpModule():
    global server, tmp, rsa
    logging.disable(logging.CRITICAL)
    tmp = tempfile.TemporaryDirectory()
    server = Server(0, Path(tmp.name) / "received_files")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not server.ready.wait(5):
        raise RuntimeError("server did not start")
    rsa = RSA.generate(1024, e=17)


def tearDownModule():
    logging.disable(logging.NOTSET)
    tmp.cleanup()


def connect():
    return FakeClient(HOST, server.port)


def saved_path(client_id, name):
    return Path(tmp.name) / "received_files" / client_id.hex() / name


class SessionBindingTest(unittest.TestCase):
    def setUp(self):
        self.victim = connect()
        self.addCleanup(self.victim.close)
        self.name = f"victim-{uuid.uuid4().hex[:10]}"
        self.aes_key = self.victim.setup(self.name, rsa)

    def attacker(self):
        c = connect()
        self.addCleanup(c.close)
        c.client_id = self.victim.client_id
        return c

    def test_file_needs_key_exchange_on_same_connection(self):
        a = self.attacker()
        code, _ = a.send_file("x.bin", b"data", self.aes_key)
        self.assertEqual(code, 1607)

    def test_other_connection_cannot_confirm_or_delete(self):
        self.assertEqual(
            self.victim.send_file("doc.bin", b"secret", self.aes_key)[0],
            1603,
        )
        a = self.attacker()
        self.assertEqual(a.request(902, name_field("doc.bin"))[1], 1607)
        self.assertEqual(a.request(900, name_field("doc.bin"))[1], 1607)
        path = saved_path(self.victim.client_id, "doc.bin")
        self.assertEqual(path.read_bytes(), b"secret")
        self.assertEqual(self.victim.crc_ok("doc.bin")[0], 1604)

    def test_spoofed_reconnect_does_not_break_victim(self):
        a = self.attacker()
        self.assertEqual(a.reconnect(self.name)[0], 1605)
        data = os.urandom(5000)
        code, info = self.victim.send_file("v.bin", data, self.aes_key)
        self.assertEqual(code, 1603)
        self.assertEqual(info[3], cksum_bytes(data))

    def test_confirm_only_files_from_this_connection(self):
        self.assertEqual(self.victim.crc_ok("never-sent.bin")[0], 1607)

    def test_legit_reconnect_on_new_connection(self):
        c = connect()
        self.addCleanup(c.close)
        c.client_id = self.victim.client_id
        code, payload = c.reconnect(self.name)
        self.assertEqual(code, 1605)
        new_key = PKCS1_OAEP.new(rsa).decrypt(payload[16:])
        data = os.urandom(3000)
        code, info = c.send_file("again.bin", data, new_key)
        self.assertEqual((code, info[3]), (1603, cksum_bytes(data)))
        self.assertEqual(c.crc_ok("again.bin")[0], 1604)


class QuotaTest(unittest.TestCase):
    def new_client(self):
        c = connect()
        self.addCleanup(c.close)
        key = c.setup(f"quota-{uuid.uuid4().hex[:10]}", rsa)
        return c, key

    def test_file_count_limit(self):
        c, key = self.new_client()
        with mock.patch.object(session_module, "MAX_FILES_PER_CLIENT", 2):
            self.assertEqual(c.send_file("a.bin", b"1", key)[0], 1603)
            self.assertEqual(c.send_file("b.bin", b"2", key)[0], 1603)
            self.assertEqual(c.send_file("c.bin", b"3", key)[0], 1607)
            self.assertEqual(c.send_file("a.bin", b"new", key)[0], 1603)

    def test_storage_limit(self):
        c, key = self.new_client()
        with mock.patch.object(session_module, "MAX_BYTES_PER_CLIENT", 5000):
            self.assertEqual(c.send_file("s.bin", bytes(4000), key)[0], 1603)
            self.assertEqual(c.send_file("t.bin", bytes(2000), key)[0], 1607)
            self.assertEqual(c.send_file("s.bin", bytes(4900), key)[0], 1603)

    def test_not_enough_disk_space(self):
        c, key = self.new_client()
        with mock.patch.object(session_module, "MIN_FREE_DISK", 10**18):
            self.assertEqual(c.send_file("d.bin", b"x", key)[0], 1607)
        self.assertEqual(c.send_file("d.bin", b"x", key)[0], 1603)


class ConnectionLimitTest(unittest.TestCase):
    def test_extra_connections_are_refused(self):
        limited = Server(0, Path(tmp.name) / "limited", max_connections=2)
        threading.Thread(target=limited.serve_forever, daemon=True).start()
        self.assertTrue(limited.ready.wait(5))

        first = socket.create_connection((HOST, limited.port))
        second = socket.create_connection((HOST, limited.port))
        third = socket.create_connection((HOST, limited.port))
        third.settimeout(5)
        try:
            self.assertEqual(third.recv(1), b"")
        except ConnectionResetError:
            pass
        third.close()

        first.close()
        second.close()
        time.sleep(1.5)
        with FakeClient(HOST, limited.port) as c:
            name = f"lim-{uuid.uuid4().hex[:8]}"
            self.assertEqual(c.register(name)[0], 1600)


class ClientLimitTest(unittest.TestCase):
    def test_store_refuses_beyond_limit(self):
        store = ClientStore(max_clients=2)
        store.register("a")
        store.register("b")
        with self.assertRaises(StoreFullError):
            store.register("c")


if __name__ == "__main__":
    unittest.main()
