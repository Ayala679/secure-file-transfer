import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cksum import Cksum, cksum_bytes

GIT_CKSUM = Path(r"C:\Program Files\Git\usr\bin\cksum.exe")
CKSUM_EXE = shutil.which("cksum") or (str(GIT_CKSUM) if GIT_CKSUM.exists() else None)


def system_cksum(path):
    out = subprocess.run([CKSUM_EXE, str(path)], capture_output=True, text=True, check=True)
    return int(out.stdout.split()[0])


class KnownValuesTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(cksum_bytes(b""), 4294967295)

    def test_check_string(self):
        self.assertEqual(cksum_bytes(b"123456789"), 930766865)


@unittest.skipIf(CKSUM_EXE is None, "cksum command not found")
class SystemCksumTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def compare(self, data):
        path = Path(self.tmp.name) / "f.bin"
        path.write_bytes(data)
        self.assertEqual(cksum_bytes(data), system_cksum(path))

    def test_empty(self):
        self.compare(b"")

    def test_hello(self):
        self.compare(b"hello\n")

    def test_random_100k(self):
        self.compare(os.urandom(100 * 1024))

    def test_length_over_255(self):
        self.compare(bytes(300))

    def test_chunked_update(self):
        data = os.urandom(70_000)
        c = Cksum()
        for i in range(0, len(data), 4096):
            c.update(data[i:i + 4096])
        self.assertEqual(c.digest(), cksum_bytes(data))
        self.compare(data)

    def test_digest_twice(self):
        c = Cksum()
        c.update(b"abc")
        self.assertEqual(c.digest(), c.digest())


if __name__ == "__main__":
    unittest.main()
