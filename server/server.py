import logging
import socket
import threading

from client_store import ClientStore
from config import read_port
from database import DEFAULT_DB_PATH, Database, DatabaseError
from protocol import SERVER_VERSION
from session import DEFAULT_FILES_DIR, ClientSession

CLIENT_IDLE_TIMEOUT = 5 * 60
ACCEPT_POLL_INTERVAL = 1.0
LISTEN_BACKLOG = 16

logger = logging.getLogger("server")


class Server:
    def __init__(
        self,
        port,
        files_dir=DEFAULT_FILES_DIR,
        idle_timeout=CLIENT_IDLE_TIMEOUT,
        database=None,
    ):
        self.port = port
        self.ready = threading.Event()
        self._store = ClientStore(database)
        self._files_dir = files_dir
        self._idle_timeout = idle_timeout

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
            if self._store.persistent:
                clients, files = self._store.counts()
                logger.info(
                    "database loaded: %d clients, %d files", clients, files
                )
            while True:
                try:
                    conn, address = listener.accept()
                except TimeoutError:
                    continue
                self._start_session(conn, address)

    def _start_session(self, conn, address):
        conn.settimeout(self._idle_timeout)
        session = ClientSession(conn, self._store, address, self._files_dir)
        thread = threading.Thread(
            target=session.run, name=f"client-{address[1]}", daemon=True
        )
        thread.start()


def open_database(path=DEFAULT_DB_PATH):
    try:
        database = Database(path)
    except DatabaseError as e:
        logger.error("%s - running without the database", e)
        return None
    logger.info("using database %s", database.path)
    return database


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    port = read_port()
    database = open_database()
    try:
        Server(port, database=database).serve_forever()
    except KeyboardInterrupt:
        logger.info("server stopped")
    except OSError as e:
        logger.error("cannot run server on port %d: %s", port, e)


if __name__ == "__main__":
    main()
