import struct
import unittest

import protocol
from protocol import (
    ProtocolError,
    RequestCode,
    ResponseCode,
    aes_key_payload,
    build_response,
    client_id_payload,
    decode_name,
    encode_name,
    file_received_payload,
    parse_file_packet_header,
    parse_name_payload,
    parse_public_key_payload,
    parse_request_header,
)


class ConstantsTest(unittest.TestCase):
    def test_header_sizes(self):
        self.assertEqual(protocol.REQUEST_HEADER.size, 23)
        self.assertEqual(protocol.RESPONSE_HEADER.size, 7)

    def test_version(self):
        self.assertEqual(protocol.SERVER_VERSION, 3)

    def test_request_codes(self):
        self.assertEqual(
            [c.value for c in RequestCode], [825, 826, 827, 828, 900, 901, 902]
        )

    def test_response_codes(self):
        self.assertEqual(
            [c.value for c in ResponseCode], list(range(1600, 1608))
        )

    def test_code_name(self):
        self.assertEqual(protocol.code_name(825), "825 REGISTER")
        self.assertEqual(protocol.code_name(1607), "1607 GENERAL_ERROR")
        self.assertEqual(protocol.code_name(999), "999")

    def test_field_sizes(self):
        self.assertEqual(protocol.CLIENT_ID_SIZE, 16)
        self.assertEqual(protocol.NAME_SIZE, 255)
        self.assertEqual(protocol.PUBLIC_KEY_SIZE, 160)
        self.assertEqual(protocol.AES_KEY_SIZE * 8, 256)


class HeaderTest(unittest.TestCase):
    CLIENT_ID = bytes(range(16))

    def test_parse_request_header(self):
        raw = (
            self.CLIENT_ID
            + bytes([3])
            + bytes.fromhex("3903")
            + bytes.fromhex("ff000000")
        )
        header = parse_request_header(raw)
        self.assertEqual(header.client_id, self.CLIENT_ID)
        self.assertEqual(header.version, 3)
        self.assertEqual(header.code, RequestCode.REGISTER)
        self.assertEqual(header.payload_size, 255)

    def test_request_roundtrip(self):
        raw = protocol.REQUEST_HEADER.pack(self.CLIENT_ID, 3, 828, 123456)
        self.assertEqual(
            tuple(parse_request_header(raw)), (self.CLIENT_ID, 3, 828, 123456)
        )

    def test_max_values(self):
        raw = protocol.REQUEST_HEADER.pack(
            self.CLIENT_ID, 255, 0xFFFF, 0xFFFFFFFF
        )
        header = parse_request_header(raw)
        self.assertEqual(
            (header.version, header.code, header.payload_size),
            (255, 0xFFFF, 0xFFFFFFFF),
        )

    def test_bad_header_length(self):
        for size in (0, 22, 24):
            with self.assertRaises(ProtocolError):
                parse_request_header(bytes(size))

    def test_build_response_bytes(self):
        payload = self.CLIENT_ID
        raw = build_response(ResponseCode.REGISTER_OK, payload)
        self.assertEqual(raw[:7].hex(), "03" + "4006" + "10000000")
        self.assertEqual(raw[7:], payload)

    def test_build_response_empty(self):
        self.assertEqual(
            build_response(ResponseCode.GENERAL_ERROR).hex(),
            "03" + "4706" + "00000000",
        )

    def test_response_bad_code(self):
        with self.assertRaises(struct.error):
            build_response(70000)


class NameFieldTest(unittest.TestCase):
    def field(self, raw):
        return raw.ljust(255, b"\0")

    def test_regular_name(self):
        self.assertEqual(
            decode_name(self.field(b"Michael Jackson")), "Michael Jackson"
        )

    def test_max_length(self):
        name = "a" * 254
        self.assertEqual(decode_name(encode_name(name)), name)

    def test_garbage_after_null_ignored(self):
        self.assertEqual(
            decode_name(self.field(b"file.txt\0junk")), "file.txt"
        )

    def test_encode_pads_with_zeros(self):
        raw = encode_name("abc")
        self.assertEqual(len(raw), 255)
        self.assertEqual(raw[:4], b"abc\0")
        self.assertEqual(raw[3:], bytes(252))

    def test_rejected_fields(self):
        bad = [
            b"a" * 255,
            bytes(255),
            self.field("שלום".encode()),
            self.field(b"a\nb"),
            b"abc\0",
            b"a" * 256,
        ]
        for raw in bad:
            with self.subTest(raw=raw[:10]), self.assertRaises(ProtocolError):
                decode_name(raw)

    def test_encode_rejects(self):
        with self.assertRaises(ProtocolError):
            encode_name("a" * 255)
        with self.assertRaises(UnicodeEncodeError):
            encode_name("שלום")


class PayloadTest(unittest.TestCase):
    CLIENT_ID = bytes(range(16))

    def test_name_payload(self):
        self.assertEqual(parse_name_payload(encode_name("Ayala")), "Ayala")
        for size in (254, 256):
            with self.assertRaises(ProtocolError):
                parse_name_payload(bytes(size))

    def test_public_key_payload(self):
        key = bytes(range(160))
        payload = encode_name("Ayala") + key
        self.assertEqual(len(payload), 415)
        self.assertEqual(parse_public_key_payload(payload), ("Ayala", key))
        with self.assertRaises(ProtocolError):
            parse_public_key_payload(payload[:-1])

    def test_file_packet_header(self):
        raw = (
            bytes.fromhex("10000000")
            + bytes.fromhex("05000000")
            + bytes.fromhex("0100")
            + bytes.fromhex("0300")
            + encode_name("a.bin")
        )
        self.assertEqual(len(raw), 267)
        header = parse_file_packet_header(raw)
        self.assertEqual(tuple(header), (16, 5, 1, 3, "a.bin"))

    def test_file_packet_bad_numbering(self):
        for packet, total in ((1, 0), (4, 3)):
            raw = protocol.FILE_PACKET_HEADER.pack(
                16, 5, packet, total, encode_name("a")
            )
            with self.assertRaises(ProtocolError):
                parse_file_packet_header(raw)

    def test_response_payload_sizes(self):
        self.assertEqual(len(client_id_payload(self.CLIENT_ID)), 16)
        self.assertEqual(len(aes_key_payload(self.CLIENT_ID, bytes(128))), 144)
        self.assertEqual(
            len(file_received_payload(self.CLIENT_ID, 16, "a.bin", 1)), 279
        )

    def test_file_received_bytes(self):
        raw = file_received_payload(self.CLIENT_ID, 0x20, "x", 0x01020304)
        self.assertEqual(raw[:16], self.CLIENT_ID)
        self.assertEqual(raw[16:20].hex(), "20000000")
        self.assertEqual(raw[20:22], b"x\0")
        self.assertEqual(raw[-4:].hex(), "04030201")

    def test_bad_client_id(self):
        with self.assertRaises(ProtocolError):
            client_id_payload(bytes(15))


if __name__ == "__main__":
    unittest.main()
