"""The real server with one deliberate fault, to test the client's retries.

usage: faulty_server.py <port> bad_cksum | bad_cksum_once | file_error
  bad_cksum       1603 always carries a wrong cksum -> 901 x3, then 902
  bad_cksum_once  only the first 1603 is wrong -> 901, resend, 900
  file_error      every file gets 1607 -> client retries 3 times, then Fatal
"""
import importlib
import logging
import sys
from pathlib import Path


def main():
    port, mode = int(sys.argv[1]), sys.argv[2]
    server_dir = Path(__file__).resolve().parent.parent.parent / "server"
    sys.path.insert(0, str(server_dir))
    protocol = importlib.import_module("protocol")
    session = importlib.import_module("session")
    server = importlib.import_module("server")

    if mode in ("bad_cksum", "bad_cksum_once"):
        real_payload = session.file_received_payload
        sent = []

        def wrong_cksum(client_id, content_size, file_name, cksum):
            if mode == "bad_cksum" or not sent:
                cksum = (cksum + 1) & 0xFFFFFFFF
            sent.append(file_name)
            return real_payload(client_id, content_size, file_name, cksum)

        session.file_received_payload = wrong_cksum
    elif mode == "file_error":

        def failing(self, header):
            raw = self._read_payload(protocol.FILE_PACKET_HEADER.size)
            self._packet = protocol.parse_file_packet_header(raw)
            raise protocol.ProtocolError("forced failure for testing")

        session.ClientSession._handle_file_packet = failing
    else:
        sys.exit(f"unknown mode {mode}")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        server.Server(port).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
