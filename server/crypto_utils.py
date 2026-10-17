from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

from protocol import AES_KEY_SIZE

RSA_KEY_BITS = 1024
ZERO_IV = bytes(AES.block_size)


class CryptoError(Exception):
    pass


def generate_aes_key():
    return get_random_bytes(AES_KEY_SIZE)


def load_public_key(der):
    try:
        key = RSA.import_key(der)
    except (ValueError, IndexError, TypeError) as e:
        raise CryptoError(f"invalid public key: {e}") from e
    if key.has_private() or key.size_in_bits() != RSA_KEY_BITS:
        raise CryptoError("public key must be a 1024 bit RSA public key")
    return key


def encrypt_aes_key(public_key_der, aes_key):
    key = load_public_key(public_key_der)
    return PKCS1_OAEP.new(key).encrypt(aes_key)


class AesCbcDecryptor:
    def __init__(self, key):
        if len(key) != AES_KEY_SIZE:
            raise CryptoError("bad AES key size")
        self._cipher = AES.new(key, AES.MODE_CBC, iv=ZERO_IV)
        self._partial = b""
        self._last_block = b""

    def update(self, data):
        data = self._partial + data
        whole = len(data) - len(data) % AES.block_size
        self._partial = data[whole:]
        if whole == 0:
            return b""
        plain = self._last_block + self._cipher.decrypt(data[:whole])
        self._last_block = plain[-AES.block_size:]
        return plain[:-AES.block_size]

    def finish(self):
        if self._partial or not self._last_block:
            raise CryptoError("ciphertext length is not a multiple of the block size")
        try:
            return unpad(self._last_block, AES.block_size)
        except ValueError as e:
            raise CryptoError("bad padding") from e
