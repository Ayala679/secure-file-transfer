import logging
import threading
import unittest

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


if __name__ == "__main__":
    unittest.main()
