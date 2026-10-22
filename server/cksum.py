CRC_POLY = 0x04C11DB7
CRC_MASK = 0xFFFFFFFF
TOP_BIT = 0x80000000
BYTE_MASK = 0xFF


def _build_table():
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ CRC_POLY) if c & TOP_BIT else (c << 1)
        table.append(c & CRC_MASK)
    return table


_TABLE = _build_table()


class Cksum:

    def __init__(self):
        self._crc = 0
        self._length = 0

    def _feed(self, data):
        crc = self._crc
        table = _TABLE
        for b in data:
            crc = ((crc << 8) & CRC_MASK) ^ table[(crc >> 24) ^ b]
        self._crc = crc

    def update(self, data):
        self._feed(data)
        self._length += len(data)

    def digest(self):
        saved = self._crc
        n = self._length
        tail = bytearray()
        while n:
            tail.append(n & BYTE_MASK)
            n >>= 8
        self._feed(tail)
        result = ~self._crc & CRC_MASK
        self._crc = saved
        return result


def cksum_bytes(data):
    c = Cksum()
    c.update(data)
    return c.digest()
