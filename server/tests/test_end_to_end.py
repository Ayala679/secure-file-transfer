import logging
import os
import tempfile
import threading
import unittest
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from fake_client import FILE_PACKET, FakeClient, encrypt_file, name_field

from cksum import cksum_bytes
from server import Server

HOST = "127.0.0.1"


def setUpModule():
    global server, files_tmp
    logging.disable(logging.CRITICAL)
    files_tmp = tempfile.TemporaryDirectory()
    server = Server(0, Path(files_tmp.name) / "received_files")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not server.ready.wait(5):
        raise RuntimeError("server did not start")


def tearDownModule():
    logging.disable(logging.NOTSET)
    files_tmp.cleanup()


def files_dir():
    return Path(files_tmp.name) / "received_files"


def connect():
    return FakeClient(HOST, server.port)


def server_store():
    return server._store


class RegisterEndToEndTest(unittest.TestCase):
    def test_register(self):
        with connect() as c:
            code, client_id = c.register("e2e-user")
        self.assertEqual(code, 1600)
        self.assertEqual(len(client_id), 16)

    def test_duplicate_from_another_connection(self):
        with connect() as c:
            c.register("e2e-dup")
        with connect() as c:
            self.assertEqual(c.register("e2e-dup"), (1601, b""))

    def test_unknown_code_then_server_still_alive(self):
        with connect() as c:
            self.assertEqual(c.request(999), (3, 1607, b""))
        with connect() as c:
            self.assertEqual(c.register("e2e-after-error")[0], 1600)


class PublicKeyEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA.generate(1024, e=17)
        cls.public_der = cls.rsa.public_key().export_key("DER")

    def test_receives_encrypted_aes_key(self):
        with connect() as c:
            c.register("pk-user")
            code, payload = c.send_public_key("pk-user", self.public_der)
        self.assertEqual(code, 1602)
        self.assertEqual(payload[:16], c.client_id)
        aes_key = PKCS1_OAEP.new(self.rsa).decrypt(payload[16:])
        self.assertEqual(len(aes_key), 32)
        self.assertEqual(server_store().get(c.client_id).aes_key, aes_key)
        self.assertEqual(server_store().get(c.client_id).public_key, self.public_der)

    def test_unregistered_client_id(self):
        with connect() as c:
            c.client_id = b"\x01" * 16
            self.assertEqual(c.send_public_key("nobody", self.public_der), (1607, b""))

    def test_name_mismatch(self):
        with connect() as c:
            c.register("pk-owner")
            self.assertEqual(c.send_public_key("someone-else", self.public_der), (1607, b""))

    def test_bad_key(self):
        with connect() as c:
            c.register("pk-bad")
            self.assertEqual(c.send_public_key("pk-bad", bytes(160)), (1607, b""))
            self.assertIsNone(server_store().get(c.client_id).public_key)

    def test_second_key_gives_new_aes(self):
        with connect() as c:
            c.register("pk-twice")
            first = c.send_public_key("pk-twice", self.public_der)[1]
            second = c.send_public_key("pk-twice", self.public_der)[1]
        decrypt = PKCS1_OAEP.new(self.rsa).decrypt
        self.assertNotEqual(decrypt(first[16:]), decrypt(second[16:]))


class ReconnectEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA.generate(1024, e=17)
        cls.public_der = cls.rsa.public_key().export_key("DER")

    def test_reconnect_on_new_connection(self):
        with connect() as c:
            c.register("rc-user")
            c.send_public_key("rc-user", self.public_der)
            client_id = c.client_id
        with connect() as c:
            c.client_id = client_id
            code, payload = c.reconnect("rc-user")
        self.assertEqual(code, 1605)
        self.assertEqual(payload[:16], client_id)
        aes_key = PKCS1_OAEP.new(self.rsa).decrypt(payload[16:])
        self.assertEqual(server_store().get(client_id).aes_key, aes_key)

    def test_unknown_name(self):
        with connect() as c:
            c.client_id = b"\x02" * 16
            self.assertEqual(c.reconnect("rc-nobody"), (1606, b"\x02" * 16))

    def test_registered_without_public_key(self):
        with connect() as c:
            c.register("rc-nokey")
            self.assertEqual(c.reconnect("rc-nokey"), (1606, c.client_id))

    def test_wrong_client_id(self):
        with connect() as c:
            c.register("rc-owner")
            c.send_public_key("rc-owner", self.public_der)
            c.client_id = b"\x03" * 16
            self.assertEqual(c.reconnect("rc-owner")[0], 1606)


class FileTransferEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA.generate(1024, e=17)
        cls.counter = 0

    def new_client(self):
        FileTransferEndToEndTest.counter += 1
        c = connect()
        self.addCleanup(c.close)
        aes_key = c.setup(f"ft-user-{self.counter}", self.rsa)
        return c, aes_key

    def saved(self, client, name):
        return files_dir() / client.client_id.hex() / name

    def check_transfer(self, data, chunk_size, name="data.bin"):
        c, aes_key = self.new_client()
        code, (cid, size, got_name, crc) = c.send_file(name, data, aes_key, chunk_size)
        self.assertEqual(code, 1603)
        self.assertEqual(cid, c.client_id)
        self.assertEqual(size, (len(data) // 16 + 1) * 16)
        self.assertEqual(got_name, name)
        self.assertEqual(crc, cksum_bytes(data))
        self.assertEqual(self.saved(c, name).read_bytes(), data)
        self.assertFalse(server_store().get_file(c.client_id, name).verified)
        return c

    def test_100k_in_64k_packets(self):
        self.check_transfer(os.urandom(100 * 1024), 64 * 1024)

    def test_100k_in_1k_packets(self):
        self.check_transfer(os.urandom(100 * 1024), 1024)

    def test_odd_packet_size(self):
        self.check_transfer(os.urandom(5000), 1000)

    def test_empty_file(self):
        self.check_transfer(b"", 64 * 1024, "empty.txt")

    def test_no_temp_files_left(self):
        c = self.check_transfer(os.urandom(3000), 1024, "clean.bin")
        leftovers = [p.name for p in self.saved(c, "x").parent.iterdir() if p.suffix in (".enc", ".part")]
        self.assertEqual(leftovers, [])

    def test_path_traversal_name(self):
        c, aes_key = self.new_client()
        code, info = c.send_file("../../evil.txt", b"evil", aes_key)
        self.assertEqual(code, 1603)
        self.assertEqual(info[2], "../../evil.txt")
        self.assertEqual(self.saved(c, "evil.txt").read_bytes(), b"evil")
        self.assertFalse((files_dir().parent / "evil.txt").exists())

    def test_reserved_name_rejected(self):
        c, aes_key = self.new_client()
        self.assertEqual(c.send_file("CON", b"x", aes_key), (1607, b""))

    def test_file_before_key_exchange_skipped(self):
        with connect() as c:
            c.register("ft-nokey")
            code, _ = c.send_file("a.bin", os.urandom(100 * 1024), bytes(32))
            self.assertEqual(code, 1607)
            self.assertEqual(c.register("ft-same-connection")[0], 1600)

    def test_content_size_changes_midway(self):
        c, aes_key = self.new_client()
        enc = encrypt_file(aes_key, os.urandom(4000))
        first = FILE_PACKET.pack(len(enc), 4000, 1, 2, name_field("m.bin"))
        second = FILE_PACKET.pack(len(enc) + 16, 4000, 2, 2, name_field("m.bin"))
        c.send(828, first + enc[:2000])
        c.send(828, second + enc[2000:])
        self.assertEqual(c.receive()[1], 1607)
        self.assertEqual(c.reconnect(f"ft-user-{self.counter}")[0], 1605)

    def test_content_size_not_block_multiple(self):
        c, _ = self.new_client()
        c.send(828, FILE_PACKET.pack(17, 1, 1, 1, name_field("bad.bin")) + bytes(17))
        self.assertEqual(c.receive()[1], 1607)

    def test_last_packet_but_incomplete(self):
        c, aes_key = self.new_client()
        enc = encrypt_file(aes_key, os.urandom(100))
        c.send(828, FILE_PACKET.pack(len(enc), 100, 1, 1, name_field("short.bin")) + enc[:16])
        self.assertEqual(c.receive()[1], 1607)

    def test_resend_same_file(self):
        c, aes_key = self.new_client()
        data = os.urandom(2000)
        self.assertEqual(c.send_file("again.bin", data, aes_key)[0], 1603)
        self.assertEqual(c.send_file("again.bin", data, aes_key)[0], 1603)
        self.assertEqual(self.saved(c, "again.bin").read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
