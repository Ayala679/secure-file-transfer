"""Minimal protocol client used to test the server without the C++ client."""
import socket
import struct
import sys

CLIENT_VERSION = 3
REQUEST_HEADER = struct.Struct("<16sBHI")
RESPONSE_HEADER = struct.Struct("<BHI")


def name_field(name):
    return name.encode("ascii").ljust(255, b"\0")


class FakeClient:
    def __init__(self, host, port, timeout=5):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.client_id = bytes(16)

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def send(self, code, payload=b"", client_id=None):
        cid = self.client_id if client_id is None else client_id
        self.sock.sendall(REQUEST_HEADER.pack(cid, CLIENT_VERSION, code, len(payload)) + payload)

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("server closed the connection")
            buf += chunk
        return buf

    def receive(self):
        version, code, size = RESPONSE_HEADER.unpack(self.recv_exact(RESPONSE_HEADER.size))
        return version, code, self.recv_exact(size)

    def request(self, code, payload=b"", client_id=None):
        self.send(code, payload, client_id)
        return self.receive()

    def register(self, name):
        _, code, payload = self.request(825, name_field(name))
        if code == 1600:
            self.client_id = payload
        return code, payload

    def send_public_key(self, name, public_key_der):
        _, code, payload = self.request(826, name_field(name) + public_key_der)
        return code, payload

    def reconnect(self, name):
        _, code, payload = self.request(827, name_field(name))
        return code, payload


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
    name = sys.argv[2] if len(sys.argv) > 2 else "test-user"
    with FakeClient("127.0.0.1", port) as client:
        code, payload = client.register(name)
        print(f"register '{name}': code {code}, client id {payload.hex() or '-'}")
