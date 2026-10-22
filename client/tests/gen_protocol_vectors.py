import importlib
import random
import sys
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

HERE = Path(__file__).resolve().parent
CLIENT_ID = bytes(range(16))
PUBLIC_KEY = bytes(i % 256 for i in range(160))
ENCRYPTED_KEY = bytes((i * 7) % 256 for i in range(128))
CKSUM_LENGTHS = (0, 1, 255, 256, 300, 65536, 100_000)
AES_KEY = bytes((i * 13 + 5) % 256 for i in range(32))
AES_SMALL_LENGTHS = (0, 1, 15, 16, 17, 100, 1000)
AES_BIG_LENGTH = 200_000
SEED = 20937


def pattern(length):
    return bytes((i * 31 + 7) % 256 for i in range(length))


def build_vectors(p):
    def request(code, payload):
        header = p.REQUEST_HEADER.pack(
            CLIENT_ID, p.CLIENT_VERSION, code, len(payload)
        )
        return header + payload

    ayala = p.encode_name("Ayala")
    data_bin = p.encode_name("data.bin")
    rc, resp = p.RequestCode, p.ResponseCode
    received = p.file_received_payload(
        CLIENT_ID, 0x00019010, "data.bin", 0xDEADBEEF
    )
    return {
        "REGISTER_REQUEST": request(rc.REGISTER, ayala),
        "PUBLIC_KEY_REQUEST": request(rc.PUBLIC_KEY, ayala + PUBLIC_KEY),
        "RECONNECT_REQUEST": request(rc.RECONNECT, ayala),
        "CRC_OK_REQUEST": request(rc.CRC_OK, data_bin),
        "FILE_PACKET_HEADER": p.FILE_PACKET_HEADER.pack(
            0x00019010, 102400, 1, 2, data_bin
        ),
        "REGISTER_OK_RESPONSE": p.build_response(
            resp.REGISTER_OK, p.client_id_payload(CLIENT_ID)
        ),
        "AES_KEY_RESPONSE": p.build_response(
            resp.AES_KEY, p.aes_key_payload(CLIENT_ID, ENCRYPTED_KEY)
        ),
        "FILE_RECEIVED_RESPONSE": p.build_response(
            resp.FILE_RECEIVED, received
        ),
        "GENERAL_ERROR_RESPONSE": p.build_response(resp.GENERAL_ERROR),
    }


def aes_encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=bytes(16))
    return cipher.encrypt(pad(data, 16))


def write_crypto_vectors(cksum):
    rng = random.Random(SEED)
    rsa = RSA.generate(1024, randfunc=rng.randbytes, e=17)
    oaep = PKCS1_OAEP.new(rsa.public_key(), randfunc=rng.randbytes)
    big_cipher = aes_encrypt(pattern(AES_BIG_LENGTH))
    big_size = len(big_cipher)
    big_crc = cksum.cksum_bytes(big_cipher)

    hex_values = {
        "RSA_PRIVATE_KEY_DER": rsa.export_key("DER", pkcs=8),
        "RSA_PUBLIC_KEY_DER": rsa.public_key().export_key("DER"),
        "AES_KEY": AES_KEY,
        "ENCRYPTED_AES_KEY": oaep.encrypt(AES_KEY),
    }
    lines = [
        "#pragma once",
        "",
        "",
        "namespace crypto_vectors {",
        "",
    ]
    for name, data in hex_values.items():
        lines.append(f"inline constexpr const char* {name} =")
        lines.append(f'    "{data.hex()}";')
    lines += [
        "",
        "struct AesVector {",
        "    unsigned length;",
        "    const char* cipherHex;",
        "};",
        "",
        "inline constexpr AesVector AES_VECTORS[] = {",
    ]
    for n in AES_SMALL_LENGTHS:
        lines.append(f'    {{{n}, "{aes_encrypt(pattern(n)).hex()}"}},')
    lines += [
        "};",
        "",
        f"inline constexpr unsigned AES_BIG_LENGTH = {AES_BIG_LENGTH};",
        f"inline constexpr unsigned AES_BIG_CIPHER_SIZE = {big_size};",
        f"inline constexpr unsigned long AES_BIG_CIPHER_CKSUM = {big_crc}ul;",
        "",
        "}",
        "",
    ]
    (HERE / "CryptoVectors.h").write_text("\n".join(lines), encoding="ascii")


def main():
    sys.path.insert(0, str(HERE.parent.parent / "server"))
    protocol = importlib.import_module("protocol")
    cksum = importlib.import_module("cksum")
    write_crypto_vectors(cksum)

    lines = [
        "#pragma once",
        "",
        "",
        "namespace vectors {",
        "",
    ]
    for name, data in build_vectors(protocol).items():
        lines.append(f'inline constexpr const char* {name} =')
        lines.append(f'    "{data.hex()}";')

    lines += [
        "",
        "struct CksumVector {",
        "    unsigned length;",
        "    unsigned long cksum;",
        "};",
        "",
        "inline constexpr CksumVector CKSUM_VECTORS[] = {",
    ]
    for n in CKSUM_LENGTHS:
        lines.append(f"    {{{n}, {cksum.cksum_bytes(pattern(n))}ul}},")
    lines += ["};", "", "}", ""]
    (HERE / "ProtocolVectors.h").write_text("\n".join(lines), encoding="ascii")


if __name__ == "__main__":
    main()
