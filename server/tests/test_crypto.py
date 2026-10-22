import os
import unittest

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

from crypto_utils import (
    AesCbcDecryptor,
    CryptoError,
    encrypt_aes_key,
    generate_aes_key,
)


def encrypt(key, plain):
    return AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(pad(plain, 16))


def decrypt_in_chunks(key, cipher, chunk):
    d = AesCbcDecryptor(key)
    pieces = [cipher[i:i + chunk] for i in range(0, len(cipher), chunk)]
    out = b"".join(d.update(p) for p in pieces)
    return out + d.finish()


class AesKeyTest(unittest.TestCase):
    def test_size_and_randomness(self):
        a, b = generate_aes_key(), generate_aes_key()
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, b)


class RsaEncryptTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = RSA.generate(1024, e=17)
        cls.public_der = cls.private_key.public_key().export_key("DER")

    def test_public_key_is_160_bytes(self):
        self.assertEqual(len(self.public_der), 160)

    def test_roundtrip(self):
        aes_key = generate_aes_key()
        encrypted = encrypt_aes_key(self.public_der, aes_key)
        self.assertEqual(len(encrypted), 128)
        decrypted = PKCS1_OAEP.new(self.private_key).decrypt(encrypted)
        self.assertEqual(decrypted, aes_key)

    def test_garbage_key(self):
        for bad in (b"", bytes(160), b"\x30" * 160):
            with self.subTest(bad=bad[:4]), self.assertRaises(CryptoError):
                encrypt_aes_key(bad, generate_aes_key())

    def test_wrong_key_size(self):
        der = RSA.generate(2048).public_key().export_key("DER")
        with self.assertRaises(CryptoError):
            encrypt_aes_key(der, generate_aes_key())

    def test_private_key_rejected(self):
        with self.assertRaises(CryptoError):
            encrypt_aes_key(
                self.private_key.export_key("DER"), generate_aes_key()
            )


class AesDecryptTest(unittest.TestCase):
    def setUp(self):
        self.key = generate_aes_key()

    def test_chunk_sizes(self):
        plain = os.urandom(100_000)
        cipher = encrypt(self.key, plain)
        for chunk in (1, 7, 16, 4096, 65536, len(cipher)):
            with self.subTest(chunk=chunk):
                self.assertEqual(
                    decrypt_in_chunks(self.key, cipher, chunk), plain
                )

    def test_padding_edge_lengths(self):
        for size in (0, 1, 15, 16, 17, 32):
            plain = os.urandom(size)
            cipher = encrypt(self.key, plain)
            self.assertEqual(len(cipher), (size // 16 + 1) * 16)
            self.assertEqual(decrypt_in_chunks(self.key, cipher, 5), plain)

    def test_length_not_multiple_of_block(self):
        cipher = encrypt(self.key, b"hello")
        with self.assertRaises(CryptoError):
            decrypt_in_chunks(self.key, cipher[:-1], 16)

    def test_empty_ciphertext(self):
        with self.assertRaises(CryptoError):
            AesCbcDecryptor(self.key).finish()

    def test_bad_padding(self):
        raw = AES.new(self.key, AES.MODE_CBC, iv=bytes(16)).encrypt(bytes(32))
        with self.assertRaises(CryptoError):
            decrypt_in_chunks(self.key, raw, 16)

    def test_wrong_key(self):
        cipher = encrypt(self.key, b"secret data")
        try:
            result = decrypt_in_chunks(generate_aes_key(), cipher, 16)
        except CryptoError:
            return
        self.assertNotEqual(result, b"secret data")

    def test_bad_key_size(self):
        with self.assertRaises(CryptoError):
            AesCbcDecryptor(bytes(16))


if __name__ == "__main__":
    unittest.main()
