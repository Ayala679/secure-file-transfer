import os
import tempfile
from pathlib import Path

from cksum import Cksum
from crypto_utils import AesCbcDecryptor
from protocol import ProtocolError

AES_BLOCK_SIZE = 16
MAX_CONTENT_SIZE = 1 << 30
COPY_CHUNK_SIZE = 64 * 1024
FORBIDDEN_CHARS = set('<>:"|?*')
WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_file_name(name):
    base = name.replace("\\", "/").rsplit("/", 1)[-1].rstrip(" .")
    if (
        not base
        or base in (".", "..")
        or any(c in FORBIDDEN_CHARS for c in base)
        or base.split(".")[0].upper() in WINDOWS_RESERVED
    ):
        raise ProtocolError(f"unsafe file name '{name}'")
    return base


def same_file(a, b):
    return (a.content_size, a.orig_size, a.total_packets, a.file_name) == (
        b.content_size,
        b.orig_size,
        b.total_packets,
        b.file_name,
    )


def _remove_quietly(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


class IncomingFile:
    def __init__(self, folder, first_packet):
        size = first_packet.content_size
        if size == 0 or size % AES_BLOCK_SIZE or size > MAX_CONTENT_SIZE:
            raise ProtocolError(f"invalid content size {size}")

        self.packet = first_packet
        self.received = 0
        self.target = Path(folder) / safe_file_name(first_packet.file_name)
        self.target.parent.mkdir(parents=True, exist_ok=True)
        fd, enc_path = tempfile.mkstemp(dir=self.target.parent, suffix=".enc")
        self._enc_path = enc_path
        self._enc_file = os.fdopen(fd, "wb")

    def belongs(self, packet):
        return same_file(self.packet, packet)

    def write(self, chunk):
        if self.received + len(chunk) > self.packet.content_size:
            raise ProtocolError("received more data than content size")
        self._enc_file.write(chunk)
        self.received += len(chunk)

    @property
    def complete(self):
        return self.received == self.packet.content_size

    def finish(self, aes_key):
        self._enc_file.close()
        decryptor = AesCbcDecryptor(aes_key)
        crc = Cksum()
        plain_size = 0
        fd, part_path = tempfile.mkstemp(
            dir=self.target.parent, suffix=".part"
        )
        try:
            with open(self._enc_path, "rb") as src, os.fdopen(fd, "wb") as dst:
                while chunk := src.read(COPY_CHUNK_SIZE):
                    plain = decryptor.update(chunk)
                    dst.write(plain)
                    crc.update(plain)
                    plain_size += len(plain)
                plain = decryptor.finish()
                dst.write(plain)
                crc.update(plain)
                plain_size += len(plain)
            os.replace(part_path, self.target)
        except BaseException:
            _remove_quietly(part_path)
            raise
        finally:
            _remove_quietly(self._enc_path)
        return crc.digest(), plain_size

    def discard(self):
        self._enc_file.close()
        _remove_quietly(self._enc_path)
