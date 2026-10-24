import logging
import threading
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime

from protocol import AES_KEY_SIZE, CLIENT_ID_SIZE, NAME_SIZE, PUBLIC_KEY_SIZE

logger = logging.getLogger(__name__)


class StoreError(Exception):
    pass


class NameTakenError(StoreError):
    pass


class UnknownClientError(StoreError):
    pass


@dataclass
class ClientRecord:
    client_id: bytes
    name: str
    public_key: bytes | None = None
    aes_key: bytes | None = None
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class FileRecord:
    client_id: bytes
    file_name: str
    path: str
    verified: bool = False


def _is_blob(value, size):
    return isinstance(value, bytes) and len(value) == size


def _is_name(value):
    return (
        isinstance(value, str)
        and 0 < len(value) < NAME_SIZE
        and all(" " <= c <= "~" for c in value)
    )


def _parse_time(text):
    try:
        return datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return datetime.now()


class ClientStore:
    def __init__(self, database=None):
        self._lock = threading.Lock()
        self._clients = {}
        self._ids_by_name = {}
        self._files = {}
        self._db = database
        if database is not None:
            self._load()

    def _load(self):
        try:
            client_rows = self._db.load_clients()
            file_rows = self._db.load_files()
        except StoreError as e:
            logger.error("%s - continuing without the database", e)
            self._db = None
            return

        for client_id, name, public_key, last_seen, aes_key in client_rows:
            if not _is_blob(client_id, CLIENT_ID_SIZE) or not _is_name(name):
                logger.warning("skipping a bad client row in the database")
                continue
            if not _is_blob(public_key, PUBLIC_KEY_SIZE):
                public_key = None
            if not _is_blob(aes_key, AES_KEY_SIZE):
                aes_key = None
            record = ClientRecord(
                client_id, name, public_key, aes_key, _parse_time(last_seen)
            )
            self._clients[client_id] = record
            self._ids_by_name[name] = client_id

        for client_id, file_name, path, verified in file_rows:
            if client_id in self._clients and _is_name(file_name):
                self._files[(client_id, file_name)] = FileRecord(
                    client_id, file_name, path, bool(verified)
                )

    @property
    def persistent(self):
        return self._db is not None

    def counts(self):
        with self._lock:
            return len(self._clients), len(self._files)

    def register(self, name):
        with self._lock:
            if name in self._ids_by_name:
                raise NameTakenError(f"name '{name}' is already registered")
            client_id = uuid.uuid4().bytes
            while client_id in self._clients:
                client_id = uuid.uuid4().bytes
            record = ClientRecord(client_id, name)
            if self._db is not None:
                self._db.add_client(record)
            self._clients[client_id] = record
            self._ids_by_name[name] = client_id
            return replace(record)

    def get(self, client_id):
        with self._lock:
            record = self._clients.get(client_id)
            return replace(record) if record else None

    def find_by_name(self, name):
        with self._lock:
            client_id = self._ids_by_name.get(name)
            return replace(self._clients[client_id]) if client_id else None

    def _existing(self, client_id):
        try:
            return self._clients[client_id]
        except KeyError:
            raise UnknownClientError(client_id.hex()) from None

    def set_public_key(self, client_id, public_key):
        with self._lock:
            record = self._existing(client_id)
            if self._db is not None:
                self._db.set_public_key(client_id, public_key)
            record.public_key = public_key

    def set_aes_key(self, client_id, aes_key):
        with self._lock:
            record = self._existing(client_id)
            if self._db is not None:
                self._db.set_aes_key(client_id, aes_key)
            record.aes_key = aes_key

    def touch(self, client_id):
        with self._lock:
            record = self._clients.get(client_id)
            if record is None:
                return
            record.last_seen = datetime.now()
            if self._db is not None:
                try:
                    self._db.set_last_seen(client_id, record.last_seen)
                except StoreError as e:
                    logger.warning("could not save LastSeen: %s", e)

    def save_file(self, file_record):
        with self._lock:
            self._existing(file_record.client_id)
            if self._db is not None:
                self._db.save_file(file_record)
            key = (file_record.client_id, file_record.file_name)
            self._files[key] = replace(file_record)

    def get_file(self, client_id, file_name):
        with self._lock:
            record = self._files.get((client_id, file_name))
            return replace(record) if record else None

    def set_verified(self, client_id, file_name, verified):
        with self._lock:
            record = self._files.get((client_id, file_name))
            if record is None:
                raise StoreError(f"no such file {file_name}")
            if self._db is not None:
                self._db.set_verified(client_id, file_name, verified)
            record.verified = verified

    def remove_file(self, client_id, file_name):
        with self._lock:
            if self._db is not None:
                self._db.remove_file(client_id, file_name)
            return self._files.pop((client_id, file_name), None) is not None
