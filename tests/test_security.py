
import unittest
from app import app


class SecurityTests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key"
        self.client = app.test_client()

    def test_sql_injection_login(self):
        response = self.client.post(
            "/login",
            data={
                "username": "' OR '1'='1",
                "password": "wrongpassword"
            },
            follow_redirects=False
        )

        # Login must not succeed
        self.assertNotEqual(response.status_code, 302)

    def test_unauthorized_alert_access(self):
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 401)

    def test_unauthorized_detection_access(self):
        response = self.client.post("/api/run-detection")
        self.assertEqual(response.status_code, 401)

    def test_viewer_cannot_run_detection(self):
        with self.client.session_transaction() as session:
            session["username"] = "viewer1"
            session["role"] = "viewer"

        response = self.client.post("/api/run-detection")
        self.assertEqual(response.status_code, 403)

    def test_viewer_cannot_access_admin(self):
        with self.client.session_transaction() as session:
            session["username"] = "viewer1"
            session["role"] = "viewer"

        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
