import unittest

from file_transfer import safe_file_name
from protocol import ProtocolError

KEPT_AS = [
    ("normal.bin", "normal.bin"),
    ("../../evil.txt", "evil.txt"),
    ("..\\..\\evil.txt", "evil.txt"),
    ("C:\\Windows\\System32\\x.dll", "x.dll"),
    ("/etc/passwd", "passwd"),
    ("\\\\server\\share\\a.txt", "a.txt"),
    ("dir/sub/../file.bin", "file.bin"),
    ("name. ", "name"),
    ("report.pdf...", "report.pdf"),
]

REJECTED = [
    "..",
    ".",
    "dir/",
    "   ",
    "CON",
    "con.txt",
    "NUL",
    "PRN",
    "AUX.bin",
    "COM1.log",
    "LPT9",
    "x?",
    "a*b",
    "a<b",
    "a>b",
    'a"b',
    "a|b",
    "a:b",
    "file.txt:hidden",
]


class SafeFileNameTest(unittest.TestCase):
    def test_paths_reduced_to_file_name(self):
        for raw, expected in KEPT_AS:
            with self.subTest(raw=raw):
                self.assertEqual(safe_file_name(raw), expected)

    def test_dangerous_names_rejected(self):
        for raw in REJECTED:
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                safe_file_name(raw)


if __name__ == "__main__":
    unittest.main()
