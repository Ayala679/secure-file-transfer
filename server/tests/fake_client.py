"""Minimal protocol client used to test the server without the C++ client."""

import socket
import struct
import sys

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

CLIENT_VERSION = 3
REQUEST_HEADER = struct.Struct("<16sBHI")
RESPONSE_HEADER = struct.Struct("<BHI")
FILE_PACKET = struct.Struct("<IIHH255s")
FILE_RECEIVED = struct.Struct("<16sI255sI")


def encrypt_file(aes_key, data):
    return AES.new(aes_key, AES.MODE_CBC, iv=bytes(16)).encrypt(pad(data, 16))


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
        self.sock.sendall(
            REQUEST_HEADER.pack(cid, CLIENT_VERSION, code, len(payload))
            + payload
        )

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("server closed the connection")
            buf += chunk
        return buf

    def receive(self):
        version, code, size = RESPONSE_HEADER.unpack(
            self.recv_exact(RESPONSE_HEADER.size)
        )
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

    def setup(self, name, rsa_key):
        """Register + key exchange, returns the AES key."""
        self.register(name)
        code, payload = self.send_public_key(
            name, rsa_key.public_key().export_key("DER")
        )
        if code != 1602:
            raise RuntimeError(f"key exchange failed with {code}")
        return PKCS1_OAEP.new(rsa_key).decrypt(payload[16:])

    def crc_ok(self, file_name):
        return self.request(900, name_field(file_name))[1:]

    def crc_retry(self, file_name):
        self.send(901, name_field(file_name))

    def crc_abort(self, file_name):
        return self.request(902, name_field(file_name))[1:]

    def send_packets(self, file_name, encrypted, orig_size, chunk_size):
        total = max(1, -(-len(encrypted) // chunk_size))
        for i in range(total):
            start = i * chunk_size
            chunk = encrypted[start:start + chunk_size]
            header = FILE_PACKET.pack(
                len(encrypted), orig_size, i + 1, total, name_field(file_name)
            )
            self.send(828, header + chunk)

    def send_file(self, file_name, data, aes_key, chunk_size=64 * 1024):
        self.send_packets(
            file_name, encrypt_file(aes_key, data), len(data), chunk_size
        )
        _, code, payload = self.receive()
        if code == 1603:
            cid, size, name, crc = FILE_RECEIVED.unpack(payload)
            return code, (cid, size, name.split(b"\0")[0].decode(), crc)
        return code, payload


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
    name = sys.argv[2] if len(sys.argv) > 2 else "test-user"
    path = sys.argv[3] if len(sys.argv) > 3 else None
    with FakeClient("127.0.0.1", port) as client:
        aes_key = client.setup(name, RSA.generate(1024, e=17))
        print(f"registered '{name}' as {client.client_id.hex()}, got AES key")
        if path:
            with open(path, "rb") as f:
                code, info = client.send_file(
                    path.replace("\\", "/").split("/")[-1], f.read(), aes_key
                )
            crc = info[3] if code == 1603 else "-"
            print(f"send file: code {code}, server cksum {crc}")
