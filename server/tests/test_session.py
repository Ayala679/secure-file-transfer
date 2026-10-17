import logging
import socket
import threading
import unittest

from client_store import ClientStore
from protocol import (
    REQUEST_HEADER,
    RESPONSE_HEADER,
    RequestCode,
    ResponseCode,
    encode_name,
)
from session import ClientSession


def setUpModule():
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


class SessionHarness:
    def __init__(self):
        self.client, server_sock = socket.socketpair()
        self.client.settimeout(5)
        self.store = ClientStore()
        self.session = ClientSession(server_sock, self.store, ("test", 0))
        self.thread = threading.Thread(target=self.session.run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def send(self, code, payload=b"", payload_size=None, client_id=bytes(16)):
        size = len(payload) if payload_size is None else payload_size
        self.client.sendall(REQUEST_HEADER.pack(client_id, 3, code, size) + payload)

    def recv_response(self):
        raw = self._recv_exact(RESPONSE_HEADER.size)
        version, code, size = RESPONSE_HEADER.unpack(raw)
        return version, code, self._recv_exact(size)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.client.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def is_closed(self):
        return self.client.recv(1) == b""

    def stop(self):
        self.client.close()
        self.thread.join(5)


class SessionTest(unittest.TestCase):
    def setUp(self):
        self.h = SessionHarness()

    def tearDown(self):
        self.h.stop()

    def test_unknown_code(self):
        self.h.start()
        self.h.send(999)
        self.assertEqual(self.h.recv_response(), (3, ResponseCode.GENERAL_ERROR, b""))
        self.assertTrue(self.h.is_closed())

    def test_bad_payload_size(self):
        self.h.session._handlers[1] = (lambda header, payload: None, 10)
        self.h.start()
        self.h.send(1, payload_size=0xFFFFFFFF)
        self.assertEqual(self.h.recv_response()[1], ResponseCode.GENERAL_ERROR)
        self.assertTrue(self.h.is_closed())

    def test_handler_called_and_session_continues(self):
        calls = []
        self.h.session._handlers[1] = (lambda header, payload: calls.append(payload), 3)
        self.h.start()
        self.h.send(1, b"abc")
        self.h.send(1, b"xyz")
        self.h.send(999)
        self.h.recv_response()
        self.assertEqual(calls, [b"abc", b"xyz"])

    def test_header_split_in_pieces(self):
        calls = []
        self.h.session._handlers[1] = (lambda header, payload: calls.append(payload), 2)
        self.h.start()
        raw = REQUEST_HEADER.pack(bytes(16), 3, 1, 2) + b"ok"
        for b in raw:
            self.h.client.sendall(bytes([b]))
        self.h.send(999)
        self.h.recv_response()
        self.assertEqual(calls, [b"ok"])

    def test_client_disconnects_mid_header(self):
        self.h.start()
        self.h.client.sendall(b"\x00" * 10)
        self.h.client.shutdown(socket.SHUT_WR)
        self.h.thread.join(5)
        self.assertFalse(self.h.thread.is_alive())


class RegisterTest(unittest.TestCase):
    def setUp(self):
        self.h = SessionHarness().start()

    def tearDown(self):
        self.h.stop()

    def test_register_ok(self):
        self.h.send(RequestCode.REGISTER, encode_name("Ayala"))
        version, code, payload = self.h.recv_response()
        self.assertEqual((version, code), (3, ResponseCode.REGISTER_OK))
        self.assertEqual(len(payload), 16)
        self.assertEqual(self.h.store.get(payload).name, "Ayala")

    def test_duplicate_name(self):
        self.h.send(RequestCode.REGISTER, encode_name("Ayala"))
        self.h.recv_response()
        self.h.send(RequestCode.REGISTER, encode_name("Ayala"))
        self.assertEqual(self.h.recv_response(), (3, ResponseCode.REGISTER_FAILED, b""))

    def test_bad_name_field(self):
        self.h.send(RequestCode.REGISTER, b"x" * 255)
        self.assertEqual(self.h.recv_response()[1], ResponseCode.REGISTER_FAILED)

    def test_other_client_version_accepted(self):
        self.h.client.sendall(REQUEST_HEADER.pack(bytes(16), 2, RequestCode.REGISTER, 255)
                              + encode_name("old-client"))
        self.assertEqual(self.h.recv_response()[1], ResponseCode.REGISTER_OK)

    def test_client_id_ignored(self):
        self.h.send(RequestCode.REGISTER, encode_name("Ayala"), client_id=b"\xff" * 16)
        payload = self.h.recv_response()[2]
        self.assertNotEqual(payload, b"\xff" * 16)


if __name__ == "__main__":
    unittest.main()
