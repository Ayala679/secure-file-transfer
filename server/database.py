import sqlite3
from pathlib import Path

from client_store import StoreError

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "defensive.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    ID BLOB NOT NULL PRIMARY KEY CHECK (length(ID) = 16),
    Name VARCHAR(255) NOT NULL UNIQUE,
    PublicKey BLOB CHECK (PublicKey IS NULL OR length(PublicKey) = 160),
    LastSeen TEXT NOT NULL,
    AESKey BLOB CHECK (AESKey IS NULL OR length(AESKey) = 32)
);
CREATE TABLE IF NOT EXISTS files (
    ID BLOB NOT NULL REFERENCES clients(ID),
    FileName VARCHAR(255) NOT NULL,
    PathName VARCHAR(255) NOT NULL,
    Verified BOOLEAN NOT NULL DEFAULT 0,
    PRIMARY KEY (ID, FileName)
);
"""


class DatabaseError(StoreError):
    pass


class Database:
    def __init__(self, path=DEFAULT_DB_PATH):
        self.path = Path(path)
        self._conn = None
        try:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        except sqlite3.Error as e:
            if self._conn is not None:
                self._conn.close()
            raise DatabaseError(f"cannot open {self.path.name}: {e}") from e

    def close(self):
        self._conn.close()

    def _write(self, sql, params):
        try:
            with self._conn:
                self._conn.execute(sql, params)
        except sqlite3.Error as e:
            raise DatabaseError(f"database write failed: {e}") from e

    def _read(self, sql):
        try:
            return self._conn.execute(sql).fetchall()
        except sqlite3.Error as e:
            raise DatabaseError(f"database read failed: {e}") from e

    def add_client(self, record):
        self._write(
            "INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                record.client_id,
                record.name,
                record.public_key,
                record.last_seen.isoformat(),
                record.aes_key,
            ),
        )

    def set_public_key(self, client_id, public_key):
        self._write(
            "UPDATE clients SET PublicKey = ? WHERE ID = ?",
            (public_key, client_id),
        )

    def set_aes_key(self, client_id, aes_key):
        self._write(
            "UPDATE clients SET AESKey = ? WHERE ID = ?", (aes_key, client_id)
        )

    def set_last_seen(self, client_id, when):
        self._write(
            "UPDATE clients SET LastSeen = ? WHERE ID = ?",
            (when.isoformat(), client_id),
        )

    def save_file(self, record):
        self._write(
            "INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) "
            "VALUES (?, ?, ?, ?)",
            (record.client_id, record.file_name, record.path,
             record.verified),
        )

    def set_verified(self, client_id, file_name, verified):
        self._write(
            "UPDATE files SET Verified = ? WHERE ID = ? AND FileName = ?",
            (verified, client_id, file_name),
        )

    def remove_file(self, client_id, file_name):
        self._write(
            "DELETE FROM files WHERE ID = ? AND FileName = ?",
            (client_id, file_name),
        )

    def load_clients(self):
        return self._read(
            "SELECT ID, Name, PublicKey, LastSeen, AESKey FROM clients"
        )

    def load_files(self):
        return self._read(
            "SELECT ID, FileName, PathName, Verified FROM files"
        )
