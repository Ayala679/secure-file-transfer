import logging
import socket
import threading

from client_store import ClientStore
from config import read_port
from session import ClientSession

CLIENT_IDLE_TIMEOUT = 5 * 60
ACCEPT_POLL_INTERVAL = 1.0
LISTEN_BACKLOG = 16

logger = logging.getLogger("server")


class Server:
    def __init__(self, port):
        self.port = port
        self.ready = threading.Event()
        self._store = ClientStore()

    def serve_forever(self):
        with socket.create_server(("", self.port), backlog=LISTEN_BACKLOG) as listener:
            # short accept timeout so Ctrl+C works on Windows
            listener.settimeout(ACCEPT_POLL_INTERVAL)
            self.port = listener.getsockname()[1]
            self.ready.set()
            logger.info("server version 3 listening on port %d", self.port)
            while True:
                try:
                    conn, address = listener.accept()
                except TimeoutError:
                    continue
                conn.settimeout(CLIENT_IDLE_TIMEOUT)
                ClientSession(conn, self._store, address).run()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")
    port = read_port()
    try:
        Server(port).serve_forever()
    except KeyboardInterrupt:
        logger.info("server stopped")
    except OSError as e:
        logger.error("cannot run server on port %d: %s", port, e)


if __name__ == "__main__":
    main()
