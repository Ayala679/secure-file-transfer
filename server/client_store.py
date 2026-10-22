import threading
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime

MAX_CLIENTS = 10_000


class StoreError(Exception):
    pass


class NameTakenError(StoreError):
    pass


class StoreFullError(StoreError):
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
    size: int = 0
    verified: bool = False


class ClientStore:
    def __init__(self, max_clients=MAX_CLIENTS):
        self._lock = threading.Lock()
        self._clients = {}
        self._ids_by_name = {}
        self._files = {}
        self._max_clients = max_clients

    def register(self, name):
        with self._lock:
            if name in self._ids_by_name:
                raise NameTakenError(f"name '{name}' is already registered")
            if len(self._clients) >= self._max_clients:
                raise StoreFullError("too many registered clients")
            client_id = uuid.uuid4().bytes
            while client_id in self._clients:
                client_id = uuid.uuid4().bytes
            record = ClientRecord(client_id, name)
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
            self._existing(client_id).public_key = public_key

    def set_aes_key(self, client_id, aes_key):
        with self._lock:
            self._existing(client_id).aes_key = aes_key

    def touch(self, client_id):
        with self._lock:
            record = self._clients.get(client_id)
            if record:
                record.last_seen = datetime.now()

    def save_file(self, file_record):
        with self._lock:
            self._existing(file_record.client_id)
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
            record.verified = verified

    def remove_file(self, client_id, file_name):
        with self._lock:
            return self._files.pop((client_id, file_name), None) is not None

    def usage(self, client_id):
        with self._lock:
            sizes = [
                f.size for (cid, _), f in self._files.items()
                if cid == client_id
            ]
            return len(sizes), sum(sizes)
