import unittest

import protocol
from protocol import RequestCode, ResponseCode


class ConstantsTest(unittest.TestCase):
    def test_header_sizes(self):
        self.assertEqual(protocol.REQUEST_HEADER.size, 23)
        self.assertEqual(protocol.RESPONSE_HEADER.size, 7)

    def test_version(self):
        self.assertEqual(protocol.SERVER_VERSION, 3)

    def test_request_codes(self):
        self.assertEqual([c.value for c in RequestCode],
                         [825, 826, 827, 828, 900, 901, 902])

    def test_response_codes(self):
        self.assertEqual([c.value for c in ResponseCode], list(range(1600, 1608)))

    def test_field_sizes(self):
        self.assertEqual(protocol.CLIENT_ID_SIZE, 16)
        self.assertEqual(protocol.NAME_SIZE, 255)
        self.assertEqual(protocol.PUBLIC_KEY_SIZE, 160)
        self.assertEqual(protocol.AES_KEY_SIZE * 8, 256)


if __name__ == "__main__":
    unittest.main()
