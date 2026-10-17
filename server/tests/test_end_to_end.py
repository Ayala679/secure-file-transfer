import logging
import threading
import unittest

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from fake_client import FakeClient

from server import Server

HOST = "127.0.0.1"


def setUpModule():
    global server
    logging.disable(logging.CRITICAL)
    server = Server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not server.ready.wait(5):
        raise RuntimeError("server did not start")


def tearDownModule():
    logging.disable(logging.NOTSET)


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


if __name__ == "__main__":
    unittest.main()
