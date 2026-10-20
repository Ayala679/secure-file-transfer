import logging
import socket
from pathlib import Path

from client_store import FileRecord, NameTakenError, StoreError
from crypto_utils import CryptoError, encrypt_aes_key, generate_aes_key
from file_transfer import MAX_CONTENT_SIZE, IncomingFile, same_file
from protocol import (
    CLIENT_VERSION,
    FILE_PACKET_HEADER,
    NAME_SIZE,
    PUBLIC_KEY_PAYLOAD_SIZE,
    REQUEST_HEADER,
    ProtocolError,
    RequestCode,
    ResponseCode,
    aes_key_payload,
    build_response,
    client_id_payload,
    code_name,
    file_received_payload,
    parse_file_packet_header,
    parse_name_payload,
    parse_public_key_payload,
    parse_request_header,
)

RECV_CHUNK_SIZE = 64 * 1024
CLOSE_DRAIN_TIMEOUT = 1.0
CLOSE_DRAIN_LIMIT = 1024 * 1024
DEFAULT_FILES_DIR = Path(__file__).resolve().parent / "received_files"

logger = logging.getLogger(__name__)


class ConnectionClosed(Exception):
    pass


class IdleTimeout(Exception):
    pass


class ClientSession:
    def __init__(self, sock, store, address, files_dir=DEFAULT_FILES_DIR):
        self._sock = sock
        self._store = store
        self._peer = f"{address[0]}:{address[1]}"
        self._files_dir = Path(files_dir)
        self._unread = 0
        self._incoming = None
        self._packet = None
        self._rejected = None
        # code -> (handler, min payload size, max payload size)
        self._handlers = {
            RequestCode.REGISTER: (
                self._handle_register,
                NAME_SIZE,
                NAME_SIZE,
            ),
            RequestCode.PUBLIC_KEY: (
                self._handle_public_key,
                PUBLIC_KEY_PAYLOAD_SIZE,
                PUBLIC_KEY_PAYLOAD_SIZE,
            ),
            RequestCode.RECONNECT: (
                self._handle_reconnect,
                NAME_SIZE,
                NAME_SIZE,
            ),
            RequestCode.SEND_FILE: (
                self._handle_file_packet,
                FILE_PACKET_HEADER.size,
                FILE_PACKET_HEADER.size + MAX_CONTENT_SIZE,
            ),
            RequestCode.CRC_OK: (self._handle_crc_ok, NAME_SIZE, NAME_SIZE),
            RequestCode.CRC_RETRY: (
                self._handle_crc_retry,
                NAME_SIZE,
                NAME_SIZE,
            ),
            RequestCode.CRC_ABORT: (
                self._handle_crc_abort,
                NAME_SIZE,
                NAME_SIZE,
            ),
        }
        # these handlers read their own payload from the socket
        self._streamed = {RequestCode.SEND_FILE}

    def run(self):
        logger.info("[%s] connected", self._peer)
        try:
            while self._serve_one_request():
                pass
        except ConnectionClosed as e:
            logger.info(
                "[%s] connection closed %s", self._peer, e or "by client"
            )
        except IdleTimeout:
            logger.info("[%s] idle timeout, disconnecting", self._peer)
        # one bad client must never stop the server
        except Exception as e:  # noqa: BLE001
            logger.error("[%s] unexpected error: %r", self._peer, e)
        finally:
            self._drop_incoming()
            self._close_gracefully()
            logger.info("[%s] disconnected", self._peer)

    def _close_gracefully(self):
        # closing with unread data makes Windows send RST,
        # which can drop our last response
        try:
            self._sock.shutdown(socket.SHUT_WR)
            self._sock.settimeout(CLOSE_DRAIN_TIMEOUT)
            drained = 0
            while drained < CLOSE_DRAIN_LIMIT:
                chunk = self._sock.recv(RECV_CHUNK_SIZE)
                if not chunk:
                    break
                drained += len(chunk)
        except OSError:
            pass
        finally:
            self._sock.close()

    def _serve_one_request(self):
        raw = self._recv_header()
        if raw is None:
            return False
        header = parse_request_header(raw)
        logger.info(
            "[%s] <- request %s (%d bytes)",
            self._peer,
            code_name(header.code),
            header.payload_size,
        )
        if header.version != CLIENT_VERSION:
            logger.warning(
                "[%s] client version %d, expected %d - continuing",
                self._peer,
                header.version,
                CLIENT_VERSION,
            )

        entry = self._handlers.get(header.code)
        if entry is None:
            logger.warning(
                "[%s] unknown request code %d", self._peer, header.code
            )
            self._send(ResponseCode.GENERAL_ERROR)
            return False

        self._store.touch(header.client_id)
        handler, min_size, max_size = entry
        if not min_size <= header.payload_size <= max_size:
            # can't trust the rest of the stream after a bad length
            logger.warning(
                "[%s] bad payload size %d for code %d",
                self._peer,
                header.payload_size,
                header.code,
            )
            self._send(ResponseCode.GENERAL_ERROR)
            return False

        self._unread = header.payload_size
        self._packet = None
        try:
            if header.code in self._streamed:
                handler(header)
            else:
                handler(header, self._read_payload(header.payload_size))
        except (ProtocolError, StoreError, CryptoError, OSError) as e:
            logger.warning(
                "[%s] request %d failed: %s", self._peer, header.code, e
            )
            self._drop_incoming()
            self._skip_unread()
            packet = self._packet
            if (
                packet is not None
                and packet.packet_number < packet.total_packets
            ):
                # one answer per file, so wait for its last packet
                self._rejected = packet
            else:
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
        logger.info(
            "[%s] registered '%s' as %s",
            self._peer,
            name,
            record.client_id.hex(),
        )
        self._send(
            ResponseCode.REGISTER_OK, client_id_payload(record.client_id)
        )

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

        logger.info(
            "[%s] got public key from '%s', sending AES key", self._peer, name
        )
        self._send(
            ResponseCode.AES_KEY,
            aes_key_payload(header.client_id, encrypted_key),
        )

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
            self._send(
                ResponseCode.RECONNECT_DENIED,
                client_id_payload(header.client_id),
            )
            return

        self._store.set_aes_key(header.client_id, aes_key)
        logger.info(
            "[%s] '%s' reconnected, sending new AES key", self._peer, name
        )
        self._send(
            ResponseCode.RECONNECT_OK,
            aes_key_payload(header.client_id, encrypted_key),
        )

    def _handle_file_packet(self, header):
        packet = parse_file_packet_header(
            self._read_payload(FILE_PACKET_HEADER.size)
        )
        self._packet = packet

        if self._rejected is not None:
            if same_file(self._rejected, packet):
                self._skip_unread()
                if packet.packet_number == packet.total_packets:
                    self._rejected = None
                    self._send(ResponseCode.GENERAL_ERROR)
                return
            self._rejected = None

        record = self._store.get(header.client_id)
        if record is None or record.aes_key is None:
            raise ProtocolError("file sent before key exchange")

        if self._incoming is not None and not self._incoming.belongs(packet):
            raise ProtocolError(
                "packet does not match the file being received"
            )
        if self._incoming is None:
            folder = self._files_dir / header.client_id.hex()
            self._incoming = IncomingFile(folder, packet)
            logger.info(
                "[%s] receiving '%s': %d bytes in %d packets",
                self._peer,
                packet.file_name,
                packet.content_size,
                packet.total_packets,
            )

        while self._unread:
            self._incoming.write(
                self._read_payload(min(self._unread, RECV_CHUNK_SIZE))
            )
        logger.info(
            "[%s] packet %d/%d, %d/%d bytes",
            self._peer,
            packet.packet_number,
            packet.total_packets,
            self._incoming.received,
            packet.content_size,
        )

        if not self._incoming.complete:
            if packet.packet_number == packet.total_packets:
                raise ProtocolError(
                    "last packet arrived but file is incomplete"
                )
            return

        incoming, self._incoming = self._incoming, None
        cksum, plain_size = incoming.finish(record.aes_key)
        if plain_size != packet.orig_size:
            logger.warning(
                "[%s] '%s' decrypted to %d bytes, client said %d",
                self._peer,
                packet.file_name,
                plain_size,
                packet.orig_size,
            )

        relative_path = incoming.target.relative_to(
            self._files_dir.parent
        ).as_posix()
        self._store.save_file(
            FileRecord(header.client_id, packet.file_name, relative_path)
        )
        logger.info(
            "[%s] saved '%s' as %s, cksum %d",
            self._peer,
            packet.file_name,
            relative_path,
            cksum,
        )
        self._send(
            ResponseCode.FILE_RECEIVED,
            file_received_payload(
                header.client_id, packet.content_size, packet.file_name, cksum
            ),
        )

    def _received_file(self, header, payload):
        file_name = parse_name_payload(payload)
        if self._store.get(header.client_id) is None:
            raise ProtocolError(f"unknown client id {header.client_id.hex()}")
        record = self._store.get_file(header.client_id, file_name)
        if record is None:
            raise ProtocolError(f"no received file named '{file_name}'")
        return record

    def _handle_crc_ok(self, header, payload):
        record = self._received_file(header, payload)
        self._store.set_verified(header.client_id, record.file_name, True)
        logger.info(
            "[%s] '%s' verified by client", self._peer, record.file_name
        )
        self._send(ResponseCode.ACK, client_id_payload(header.client_id))

    def _handle_crc_retry(self, header, payload):
        # no response here, the client sends the file again right away
        try:
            record = self._received_file(header, payload)
        except ProtocolError as e:
            logger.warning("[%s] ignoring CRC retry: %s", self._peer, e)
            return
        logger.info(
            "[%s] CRC mismatch on '%s', waiting for resend",
            self._peer,
            record.file_name,
        )

    def _handle_crc_abort(self, header, payload):
        record = self._received_file(header, payload)
        (self._files_dir.parent / record.path).unlink(missing_ok=True)
        self._store.remove_file(header.client_id, record.file_name)
        logger.warning(
            "[%s] client gave up on '%s', file deleted",
            self._peer,
            record.file_name,
        )
        self._send(ResponseCode.ACK, client_id_payload(header.client_id))

    def _drop_incoming(self):
        if self._incoming is not None:
            self._incoming.discard()
            self._incoming = None

    def _read_payload(self, size):
        if size > self._unread:
            raise ProtocolError("payload shorter than expected")
        data = self.recv_exact(size)
        self._unread -= size
        return data

    def _skip_unread(self):
        while self._unread:
            self._read_payload(min(self._unread, RECV_CHUNK_SIZE))

    # socket errors become ConnectionClosed/IdleTimeout, so any OSError
    # that reaches a handler is a local (disk) problem
    def _recv(self, size):
        try:
            return self._sock.recv(size)
        except TimeoutError:
            raise IdleTimeout() from None
        except OSError as e:
            raise ConnectionClosed(f"({e})") from e

    def _recv_header(self):
        first = self._recv(REQUEST_HEADER.size)
        if not first:
            return None
        return first + self.recv_exact(REQUEST_HEADER.size - len(first))

    def recv_exact(self, size):
        buf = bytearray()
        while len(buf) < size:
            chunk = self._recv(min(size - len(buf), RECV_CHUNK_SIZE))
            if not chunk:
                raise ConnectionClosed()
            buf += chunk
        return bytes(buf)

    def _send(self, code, payload=b""):
        try:
            self._sock.sendall(build_response(code, payload))
        except TimeoutError:
            raise IdleTimeout() from None
        except OSError as e:
            raise ConnectionClosed(f"({e})") from e
        logger.info("[%s] -> response %s", self._peer, code_name(code))
