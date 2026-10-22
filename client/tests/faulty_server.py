import importlib
import logging
import sys
from pathlib import Path

MODES = (
    "bad_cksum",
    "bad_cksum_once",
    "file_error",
    "broken_reply_once",
)


def main():
    port, mode = int(sys.argv[1]), sys.argv[2]
    if mode not in MODES:
        sys.exit(f"mode must be one of {', '.join(MODES)}")
    server_dir = Path(__file__).resolve().parent.parent.parent / "server"
    sys.path.insert(0, str(server_dir))
    protocol = importlib.import_module("protocol")
    session = importlib.import_module("session")
    server = importlib.import_module("server")

    if mode in ("bad_cksum", "bad_cksum_once", "broken_reply_once"):
        real_payload = session.file_received_payload
        sent = []

        def faulty_reply(client_id, content_size, file_name, cksum):
            first = not sent
            sent.append(file_name)
            if mode == "bad_cksum" or (mode == "bad_cksum_once" and first):
                cksum = (cksum + 1) & 0xFFFFFFFF
            if mode == "broken_reply_once" and first:
                client_id = bytes(len(client_id))
            return real_payload(client_id, content_size, file_name, cksum)

        session.file_received_payload = faulty_reply
    elif mode == "file_error":

        def failing(self, header):
            raw = self._read_payload(protocol.FILE_PACKET_HEADER.size)
            self._packet = protocol.parse_file_packet_header(raw)
            raise protocol.ProtocolError("forced failure for testing")

        session.ClientSession._handle_file_packet = failing

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(message)s"
    )
    try:
        server.Server(port).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
