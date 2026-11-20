
import unittest
from app import app


class AuthenticationTests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key"
        self.client = app.test_client()

    def test_home_redirects_to_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)

    def test_api_requires_login(self):
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 401)

    def test_viewer_cannot_access_admin(self):
        with self.client.session_transaction() as session:
            session["username"] = "viewer1"
            session["role"] = "viewer"

        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 403)

    def test_viewer_cannot_access_audit_logs(self):
        with self.client.session_transaction() as session:
            session["username"] = "viewer1"
            session["role"] = "viewer"

        response = self.client.get("/api/audit-logs")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
