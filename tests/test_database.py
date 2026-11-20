
import unittest


def calculate_failed_logins(statuses):

    failed_count = 0

    for status in statuses:

        if status.upper() == "FAILED":
            failed_count += 1

    return failed_count


class TestDatabaseFunctions(unittest.TestCase):

    def test_failed_login_count(self):

        statuses = [
            "SUCCESS",
            "FAILED",
            "FAILED",
            "SUCCESS"
        ]

        result = calculate_failed_logins(statuses)

        self.assertEqual(result, 2)

    def test_no_failed_logins(self):

        statuses = ["SUCCESS", "SUCCESS"]

        result = calculate_failed_logins(statuses)

        self.assertEqual(result, 0)

    def test_empty_records(self):

        statuses = []

        result = calculate_failed_logins(statuses)

        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
