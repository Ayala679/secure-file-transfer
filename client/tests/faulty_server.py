import importlib
import logging
import sys
from pathlib import Path

ALWAYS = 10**9
CKSUM_MODES = {
    "bad_cksum": ALWAYS,
    "bad_cksum_once": 1,
    "bad_cksum_twice": 2,
}
ERROR_MODES = {
    "error_register": ("_handle_register", ALWAYS),
    "error_pubkey": ("_handle_public_key", ALWAYS),
    "error_confirm": ("_handle_crc_ok", ALWAYS),
}
FILE_ERROR_MODES = {"file_error": ALWAYS, "file_error_once": 1,
                    "file_error_twice": 2}
OTHER_MODES = ("broken_reply_once", "drop_mid_file")


def main():
    port, mode = int(sys.argv[1]), sys.argv[2]
    known = [*CKSUM_MODES, *ERROR_MODES, *FILE_ERROR_MODES, *OTHER_MODES]
    if mode not in known:
        sys.exit(f"mode must be one of {', '.join(known)}")
    server_dir = Path(__file__).resolve().parent.parent.parent / "server"
    sys.path.insert(0, str(server_dir))
    protocol = importlib.import_module("protocol")
    session = importlib.import_module("session")
    server = importlib.import_module("server")
    session_class = session.ClientSession

    if mode in CKSUM_MODES or mode == "broken_reply_once":
        real_payload = session.file_received_payload
        sent = []

        def faulty_reply(client_id, content_size, file_name, cksum):
            if mode in CKSUM_MODES and len(sent) < CKSUM_MODES[mode]:
                cksum = (cksum + 1) & 0xFFFFFFFF
            if mode == "broken_reply_once" and not sent:
                client_id = bytes(len(client_id))
            sent.append(file_name)
            return real_payload(client_id, content_size, file_name, cksum)

        session.file_received_payload = faulty_reply

    elif mode in ERROR_MODES:
        name, times = ERROR_MODES[mode]
        real_handler = getattr(session_class, name)
        calls = []

        def failing(self, header, payload):
            if len(calls) < times:
                calls.append(1)
                raise protocol.ProtocolError("forced failure for testing")
            return real_handler(self, header, payload)

        setattr(session_class, name, failing)

    elif mode in FILE_ERROR_MODES:
        times = FILE_ERROR_MODES[mode]
        real_file_handler = session_class._handle_file_packet
        failed = []

        def failing_file(self, header):
            if len(failed) >= times:
                return real_file_handler(self, header)
            raw = self._read_payload(protocol.FILE_PACKET_HEADER.size)
            self._packet = protocol.parse_file_packet_header(raw)
            if self._packet.packet_number == self._packet.total_packets:
                failed.append(1)
            raise protocol.ProtocolError("forced failure for testing")

        session_class._handle_file_packet = failing_file

    elif mode == "drop_mid_file":
        real_file_handler = session_class._handle_file_packet
        dropped = []

        def dropping(self, header):
            if dropped:
                return real_file_handler(self, header)
            dropped.append(1)
            raise session.ConnectionClosed("(dropped for testing)")

        session_class._handle_file_packet = dropping

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(message)s"
    )
    try:
        server.Server(port).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
