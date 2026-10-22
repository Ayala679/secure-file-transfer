import logging
import socket
import threading

from client_store import ClientStore
from config import read_port
from protocol import SERVER_VERSION
from session import DEFAULT_FILES_DIR, ClientSession

CLIENT_IDLE_TIMEOUT = 5 * 60
ACCEPT_POLL_INTERVAL = 1.0
LISTEN_BACKLOG = 16
MAX_CONNECTIONS = 64

logger = logging.getLogger("server")


class Server:
    def __init__(
        self,
        port,
        files_dir=DEFAULT_FILES_DIR,
        idle_timeout=CLIENT_IDLE_TIMEOUT,
        max_connections=MAX_CONNECTIONS,
    ):
        self.port = port
        self.ready = threading.Event()
        self._store = ClientStore()
        self._files_dir = files_dir
        self._idle_timeout = idle_timeout
        self._slots = threading.BoundedSemaphore(max_connections)

    def serve_forever(self):
        with socket.create_server(
            ("", self.port), backlog=LISTEN_BACKLOG
        ) as listener:
            listener.settimeout(ACCEPT_POLL_INTERVAL)
            self.port = listener.getsockname()[1]
            self.ready.set()
            logger.info(
                "server version %d listening on port %d",
                SERVER_VERSION,
                self.port,
            )
            logger.info("received files are stored in %s", self._files_dir)
            while True:
                try:
                    conn, address = listener.accept()
                except TimeoutError:
                    continue
                self._start_session(conn, address)

    def _start_session(self, conn, address):
        if not self._slots.acquire(blocking=False):
            logger.warning(
                "too many connections, refusing %s:%d", *address[:2]
            )
            conn.close()
            return
        conn.settimeout(self._idle_timeout)
        session = ClientSession(conn, self._store, address, self._files_dir)
        thread = threading.Thread(
            target=self._run_session,
            args=(session,),
            name=f"client-{address[1]}",
            daemon=True,
        )
        thread.start()

    def _run_session(self, session):
        try:
            session.run()
        finally:
            self._slots.release()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    port = read_port()
    try:
        Server(port).serve_forever()
    except KeyboardInterrupt:
        logger.info("server stopped")
    except OSError as e:
        logger.error("cannot run server on port %d: %s", port, e)


if __name__ == "__main__":
    main()
