from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from protocol import AES_KEY_SIZE

RSA_KEY_BITS = 1024


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
