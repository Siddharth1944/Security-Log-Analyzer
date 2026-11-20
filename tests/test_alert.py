
import sqlite3
import unittest


class TestDuplicateRecords(unittest.TestCase):

    def setUp(self):

        self.connection = sqlite3.connect(":memory:")

        self.connection.execute("""
            CREATE TABLE login_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                username TEXT,
                ip_address TEXT,
                status TEXT,
                UNIQUE(timestamp, username, ip_address, status)
            )
        """)

    def tearDown(self):

        self.connection.close()

    def test_duplicate_prevention(self):

        query = """
            INSERT OR IGNORE INTO login_logs
            (timestamp, username, ip_address, status)
            VALUES (?, ?, ?, ?)
        """

        record = (
            "2026-11-18 10:00:00",
            "admin",
            "192.168.1.15",
            "FAILED"
        )

        self.connection.execute(query, record)
        self.connection.execute(query, record)

        self.connection.commit()

        count = self.connection.execute(
            "SELECT COUNT(*) FROM login_logs"
        ).fetchone()[0]

        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
