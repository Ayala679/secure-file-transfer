import unittest

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from crypto_utils import CryptoError, encrypt_aes_key, generate_aes_key


class AesKeyTest(unittest.TestCase):
    def test_size_and_randomness(self):
        a, b = generate_aes_key(), generate_aes_key()
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, b)


class RsaEncryptTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # CryptoPP uses e=17 by default, which gives a 160 byte X.509 key
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
            encrypt_aes_key(self.private_key.export_key("DER"), generate_aes_key())


if __name__ == "__main__":
    unittest.main()
