import logging
import os
import socket
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from Crypto.PublicKey import RSA
from fake_client import (
    FILE_PACKET,
    REQUEST_HEADER,
    FakeClient,
    encrypt_file,
    name_field,
)

from file_transfer import MAX_CONTENT_SIZE
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


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def wait_for(condition, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


class MaliciousInputTest(unittest.TestCase):
    def assert_server_alive(self):
        with connect() as c:
            self.assertEqual(c.register(unique("alive"))[0], 1600)

    def assert_closed(self, client):
        client.sock.settimeout(5)
        self.assertEqual(client.sock.recv(1), b"")

    def tearDown(self):
        self.assert_server_alive()

    def test_huge_payload_size(self):
        with connect() as c:
            c.sock.sendall(REQUEST_HEADER.pack(bytes(16), 3, 825, 0xFFFFFFFF))
            self.assertEqual(c.receive()[1], 1607)
            self.assert_closed(c)

    def test_file_payload_over_limit(self):
        with connect() as c:
            size = FILE_PACKET.size + MAX_CONTENT_SIZE + 1
            c.sock.sendall(REQUEST_HEADER.pack(bytes(16), 3, 828, size))
            self.assertEqual(c.receive()[1], 1607)

    def test_declared_content_size_over_limit(self):
        with connect() as c:
            c.setup(unique("big"), rsa)
            header = FILE_PACKET.pack(
                0xFFFFFFF0, 1, 1, 1, name_field("big.bin")
            )
            c.send(828, header + bytes(16))
            self.assertEqual(c.receive()[1], 1607)

    def test_random_garbage(self):
        for _ in range(20):
            with connect() as c:
                c.sock.sendall(os.urandom(500))
                c.sock.settimeout(5)
                try:
                    while c.sock.recv(4096):
                        pass
                except (ConnectionError, TimeoutError):
                    pass

    def test_unknown_codes(self):
        for code in (0, 1, 824, 829, 899, 903, 1600, 0xFFFF):
            with connect() as c:
                self.assertEqual(c.request(code, b"x" * 10)[1], 1607)

    def test_name_without_terminator(self):
        with connect() as c:
            self.assertEqual(c.request(825, b"A" * 255)[1], 1601)

    def test_fake_client_id(self):
        with connect() as c:
            c.client_id = os.urandom(16)
            self.assertEqual(c.reconnect("someone")[0], 1606)
            self.assertEqual(c.request(900, name_field("x"))[1], 1607)
            self.assertEqual(c.request(902, name_field("x"))[1], 1607)

    def test_disconnect_in_middle_of_packet(self):
        files_root = Path(tmp.name) / "received_files"
        with connect() as c:
            aes_key = c.setup(unique("cut"), rsa)
            enc = encrypt_file(aes_key, os.urandom(50_000))
            header = FILE_PACKET.pack(
                len(enc), 50_000, 1, 1, name_field("cut.bin")
            )
            c.sock.sendall(
                REQUEST_HEADER.pack(
                    c.client_id, 3, 828, len(header) + len(enc)
                )
                + header
            )
            c.sock.sendall(enc[:10_000])
            folder = files_root / c.client_id.hex()
            self.assertTrue(wait_for(lambda: any(folder.glob("*.enc"))))
        self.assertTrue(wait_for(lambda: not any(folder.iterdir())))

    def test_partial_header_then_close(self):
        s = socket.create_connection((HOST, server.port))
        s.sendall(b"\x00" * 10)
        s.close()

    def test_many_quick_connections(self):
        for _ in range(50):
            socket.create_connection((HOST, server.port)).close()


class DiskErrorTest(unittest.TestCase):
    def test_cannot_write_files_returns_1607(self):
        blocker = Path(tmp.name) / "not_a_dir"
        blocker.write_text("x")
        broken = Server(0, blocker / "received_files")
        threading.Thread(target=broken.serve_forever, daemon=True).start()
        self.assertTrue(broken.ready.wait(5))
        with FakeClient(HOST, broken.port) as c:
            aes_key = c.setup(unique("disk"), rsa)
            self.assertEqual(c.send_file("a.bin", b"data", aes_key)[0], 1607)
            self.assertEqual(c.register(unique("disk-after"))[0], 1600)


if __name__ == "__main__":
    unittest.main()
