import tempfile
import unittest
from pathlib import Path

from config import DEFAULT_PORT, read_port


class ReadPortTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "port.info"

    def tearDown(self):
        self.tmp.cleanup()

    def check_fallback(self, content):
        if content is not None:
            self.path.write_bytes(content)
        with self.assertLogs("config", level="WARNING"):
            self.assertEqual(read_port(self.path), DEFAULT_PORT)

    def test_valid(self):
        self.path.write_text("1234\n")
        self.assertEqual(read_port(self.path), 1234)

    def test_missing_file(self):
        self.check_fallback(None)

    def test_empty_file(self):
        self.check_fallback(b"")

    def test_not_a_number(self):
        self.check_fallback(b"abc")

    def test_negative(self):
        self.check_fallback(b"-5")

    def test_zero(self):
        self.check_fallback(b"0")

    def test_too_big(self):
        self.check_fallback(b"70000")

    def test_non_ascii(self):
        self.check_fallback("١٢٣".encode())

    def test_utf8_bom(self):
        self.path.write_bytes(b"\xef\xbb\xbf1234\r\n")
        self.assertEqual(read_port(self.path), 1234)

    def test_directory(self):
        self.path.mkdir()
        with self.assertLogs("config", level="WARNING"):
            self.assertEqual(read_port(self.path), DEFAULT_PORT)

    def test_huge_file(self):
        self.check_fallback(b"1234" + b" " * 10_000_000)

    def test_default_location(self):
        self.assertEqual(read_port(), 1234)


if __name__ == "__main__":
    unittest.main()
