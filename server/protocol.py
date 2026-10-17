import struct
from enum import IntEnum
from typing import NamedTuple

SERVER_VERSION = 3

CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 32
CKSUM_SIZE = 4

REQUEST_HEADER = struct.Struct(f"<{CLIENT_ID_SIZE}sBHI")
RESPONSE_HEADER = struct.Struct("<BHI")
MAX_PAYLOAD_SIZE = 0xFFFFFFFF


class RequestCode(IntEnum):
    REGISTER = 825
    PUBLIC_KEY = 826
    RECONNECT = 827
    SEND_FILE = 828
    CRC_OK = 900
    CRC_RETRY = 901
    CRC_ABORT = 902


class ResponseCode(IntEnum):
    REGISTER_OK = 1600
    REGISTER_FAILED = 1601
    AES_KEY = 1602
    FILE_RECEIVED = 1603
    ACK = 1604
    RECONNECT_OK = 1605
    RECONNECT_DENIED = 1606
    GENERAL_ERROR = 1607


class ProtocolError(Exception):
    pass


class RequestHeader(NamedTuple):
    client_id: bytes
    version: int
    code: int
    payload_size: int


def parse_request_header(data):
    if len(data) != REQUEST_HEADER.size:
        raise ProtocolError(f"bad header length {len(data)}")
    return RequestHeader(*REQUEST_HEADER.unpack(data))


def build_response(code, payload=b""):
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ProtocolError("payload too large")
    return RESPONSE_HEADER.pack(SERVER_VERSION, code, len(payload)) + payload
