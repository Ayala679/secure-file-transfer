import threading
import unittest

from client_store import (
    ClientStore,
    FileRecord,
    NameTakenError,
    StoreError,
    UnknownClientError,
)


class ClientStoreTest(unittest.TestCase):
    def setUp(self):
        self.store = ClientStore()

    def test_register_and_lookup(self):
        rec = self.store.register("Ayala")
        self.assertEqual(len(rec.client_id), 16)
        self.assertEqual(self.store.get(rec.client_id).name, "Ayala")
        self.assertEqual(self.store.find_by_name("Ayala").client_id, rec.client_id)

    def test_duplicate_name(self):
        self.store.register("Ayala")
        with self.assertRaises(NameTakenError):
            self.store.register("Ayala")

    def test_unknown_lookups(self):
        self.assertIsNone(self.store.get(bytes(16)))
        self.assertIsNone(self.store.find_by_name("nobody"))

    def test_keys(self):
        rec = self.store.register("Ayala")
        self.store.set_public_key(rec.client_id, b"pub")
        self.store.set_aes_key(rec.client_id, b"aes")
        stored = self.store.get(rec.client_id)
        self.assertEqual((stored.public_key, stored.aes_key), (b"pub", b"aes"))
        with self.assertRaises(UnknownClientError):
            self.store.set_public_key(bytes(16), b"pub")

    def test_returned_record_is_a_copy(self):
        rec = self.store.register("Ayala")
        rec.name = "hacked"
        self.assertEqual(self.store.get(rec.client_id).name, "Ayala")

    def test_touch_updates_last_seen(self):
        rec = self.store.register("Ayala")
        before = self.store.get(rec.client_id).last_seen
        self.store.touch(rec.client_id)
        self.assertGreaterEqual(self.store.get(rec.client_id).last_seen, before)

    def test_files(self):
        cid = self.store.register("Ayala").client_id
        self.store.save_file(FileRecord(cid, "a.bin", "received_files/x/a.bin"))
        self.assertFalse(self.store.get_file(cid, "a.bin").verified)
        self.store.set_verified(cid, "a.bin", True)
        self.assertTrue(self.store.get_file(cid, "a.bin").verified)
        self.assertTrue(self.store.remove_file(cid, "a.bin"))
        self.assertIsNone(self.store.get_file(cid, "a.bin"))
        with self.assertRaises(StoreError):
            self.store.set_verified(cid, "a.bin", True)

    def test_file_for_unknown_client(self):
        with self.assertRaises(UnknownClientError):
            self.store.save_file(FileRecord(bytes(16), "a.bin", "p"))

    def test_parallel_register_same_name(self):
        results = []

        def worker():
            try:
                self.store.register("same")
                results.append("ok")
            except NameTakenError:
                results.append("taken")

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("ok"), 1)


if __name__ == "__main__":
    unittest.main()
