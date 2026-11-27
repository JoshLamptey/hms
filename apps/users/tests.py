from types import SimpleNamespace
from unittest.mock import patch

import jwt
from django.test import SimpleTestCase

from apps.users.auth import Authenticator


class AccessTokenLifetimeTests(SimpleTestCase):
    @patch("apps.users.auth.config", return_value="test-secret")
    def test_access_token_expires_after_fifteen_minutes(self, _config):
        user = SimpleNamespace(
            id=42,
            uid="user-uid",
            first_name="Test",
            last_name="User",
            role=None,
            org_slug="tenant",
        )

        token = Authenticator().generate_access_token(user)
        payload = jwt.decode(token, options={"verify_signature": False})

        self.assertEqual(payload["exp"] - payload["iat"], 15 * 60)
