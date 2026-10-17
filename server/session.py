import logging

from client_store import NameTakenError, StoreError
from crypto_utils import CryptoError, encrypt_aes_key, generate_aes_key
from protocol import (
    CLIENT_VERSION,
    NAME_SIZE,
    PUBLIC_KEY_PAYLOAD_SIZE,
    REQUEST_HEADER,
    ProtocolError,
    RequestCode,
    ResponseCode,
    aes_key_payload,
    build_response,
    client_id_payload,
    parse_name_payload,
    parse_public_key_payload,
    parse_request_header,
)

RECV_CHUNK_SIZE = 64 * 1024

logger = logging.getLogger(__name__)


class ConnectionClosed(Exception):
    pass


class ClientSession:
    def __init__(self, sock, store, address):
        self._sock = sock
        self._store = store
        self._peer = f"{address[0]}:{address[1]}"
        # code -> (handler, exact payload size)
        self._handlers = {
            RequestCode.REGISTER: (self._handle_register, NAME_SIZE),
            RequestCode.PUBLIC_KEY: (self._handle_public_key, PUBLIC_KEY_PAYLOAD_SIZE),
            RequestCode.RECONNECT: (self._handle_reconnect, NAME_SIZE),
        }

    def run(self):
        logger.info("[%s] connected", self._peer)
        try:
            while self._serve_one_request():
                pass
        except ConnectionClosed:
            logger.info("[%s] connection closed by client", self._peer)
        except TimeoutError:
            logger.info("[%s] idle timeout, disconnecting", self._peer)
        except OSError as e:
            logger.warning("[%s] socket error: %s", self._peer, e)
        finally:
            self._sock.close()
            logger.info("[%s] disconnected", self._peer)

    def _serve_one_request(self):
        raw = self._recv_header()
        if raw is None:
            return False
        header = parse_request_header(raw)
        logger.info("[%s] request %d, payload %d bytes", self._peer, header.code, header.payload_size)
        if header.version != CLIENT_VERSION:
            logger.warning("[%s] client version %d, expected %d - continuing",
                           self._peer, header.version, CLIENT_VERSION)

        entry = self._handlers.get(header.code)
        if entry is None:
            logger.warning("[%s] unknown request code %d", self._peer, header.code)
            self._send(ResponseCode.GENERAL_ERROR)
            return False

        self._store.touch(header.client_id)
        handler, expected_size = entry
        if header.payload_size != expected_size:
            # can't trust the rest of the stream after a bad length
            logger.warning("[%s] bad payload size %d for code %d",
                           self._peer, header.payload_size, header.code)
            self._send(ResponseCode.GENERAL_ERROR)
            return False

        payload = self.recv_exact(header.payload_size)
        try:
            handler(header, payload)
        except (ProtocolError, StoreError, CryptoError) as e:
            logger.warning("[%s] request %d failed: %s", self._peer, header.code, e)
            self._send(ResponseCode.GENERAL_ERROR)
        return True

    def _handle_register(self, header, payload):
        try:
            name = parse_name_payload(payload)
            record = self._store.register(name)
        except (ProtocolError, NameTakenError) as e:
            logger.warning("[%s] registration failed: %s", self._peer, e)
            self._send(ResponseCode.REGISTER_FAILED)
            return
        logger.info("[%s] registered '%s' as %s", self._peer, name, record.client_id.hex())
        self._send(ResponseCode.REGISTER_OK, client_id_payload(record.client_id))

    def _known_client(self, client_id, name):
        record = self._store.get(client_id)
        if record is None:
            raise ProtocolError(f"unknown client id {client_id.hex()}")
        if record.name != name:
            raise ProtocolError(f"name '{name}' does not match client id")
        return record

    def _handle_public_key(self, header, payload):
        name, public_key = parse_public_key_payload(payload)
        self._known_client(header.client_id, name)

        aes_key = generate_aes_key()
        encrypted_key = encrypt_aes_key(public_key, aes_key)
        self._store.set_public_key(header.client_id, public_key)
        self._store.set_aes_key(header.client_id, aes_key)

        logger.info("[%s] got public key from '%s', sending AES key", self._peer, name)
        self._send(ResponseCode.AES_KEY, aes_key_payload(header.client_id, encrypted_key))

    def _handle_reconnect(self, header, payload):
        try:
            name = parse_name_payload(payload)
            record = self._known_client(header.client_id, name)
            if record.public_key is None:
                raise ProtocolError("client has no public key")
            aes_key = generate_aes_key()
            encrypted_key = encrypt_aes_key(record.public_key, aes_key)
        except (ProtocolError, CryptoError) as e:
            logger.warning("[%s] reconnect rejected: %s", self._peer, e)
            self._send(ResponseCode.RECONNECT_DENIED, client_id_payload(header.client_id))
            return

        self._store.set_aes_key(header.client_id, aes_key)
        logger.info("[%s] '%s' reconnected, sending new AES key", self._peer, name)
        self._send(ResponseCode.RECONNECT_OK, aes_key_payload(header.client_id, encrypted_key))

    def _recv_header(self):
        first = self._sock.recv(REQUEST_HEADER.size)
        if not first:
            return None
        return first + self.recv_exact(REQUEST_HEADER.size - len(first))

    def recv_exact(self, size):
        buf = bytearray()
        while len(buf) < size:
            chunk = self._sock.recv(min(size - len(buf), RECV_CHUNK_SIZE))
            if not chunk:
                raise ConnectionClosed()
            buf += chunk
        return bytes(buf)

    def _send(self, code, payload=b""):
        self._sock.sendall(build_response(code, payload))
        logger.info("[%s] response %d", self._peer, code)
