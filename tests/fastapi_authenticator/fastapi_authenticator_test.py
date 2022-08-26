import unittest
from unittest.mock import MagicMock
from asyncio import Future

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from mauth_client.config import Config
from mauth_client.fastapi_authenticator import FastAPIAuthenticator, requires_authentication


class TestFastAPIAuthenticator(unittest.TestCase):
    def setUp(self) -> None:
        self.app = FastAPI()
        Config.APP_UUID = "2f746447-c212-483c-9eec-d9b0216f7613"
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.MAUTH_MODE = "local"
        Config.PRIVATE_KEY = "key"

    def test_app_configuration(self):
        try:
            FastAPIAuthenticator(self.app)
        except TypeError:
            self.fail("Shouldn't raise an exception")

    def test_app_configuration_missing_uuid(self):
        Config.APP_UUID = None
        with self.assertRaises(TypeError) as exc:
            FastAPIAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FastAPIAuthenticator requires APP_UUID and PRIVATE_KEY")

    def test_app_configuration_missing_key(self):
        Config.PRIVATE_KEY = None
        with self.assertRaises(TypeError) as exc:
            FastAPIAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FastAPIAuthenticator requires APP_UUID and PRIVATE_KEY")

    def test_app_configuration_missing_base_url(self):
        Config.MAUTH_URL = None
        with self.assertRaises(TypeError) as exc:
            FastAPIAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FastAPIAuthenticator requires MAUTH_URL and MAUTH_API_VERSION")

    def test_app_configuration_missing_version(self):
        Config.MAUTH_API_VERSION = None
        with self.assertRaises(TypeError) as exc:
            FastAPIAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FastAPIAuthenticator requires MAUTH_URL and MAUTH_API_VERSION")

    def test_app_configuration_wrong_mode(self):
        Config.MAUTH_MODE = "banana"
        with self.assertRaises(TypeError) as exc:
            FastAPIAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FastAPIAuthenticator MAUTH_MODE must be one of local or remote")

    def test_app_configuration_remote(self):
        Config.MAUTH_MODE = "remote"
        try:
            FastAPIAuthenticator(self.app)
        except TypeError:
            self.fail("Shouldn't raise an exception")

    def test_app_configuration_and_call_protected_url(self):
        authenticator = FastAPIAuthenticator()
        authenticator.init_app(self.app)

        @self.app.get("/", dependencies=[Depends(requires_authentication)])
        async def root():
            return {"msg": "helloes"}

        client = TestClient(self.app)
        response = client.get("/")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {
            "detail": (
                "Authentication Failed. No mAuth signature present; "
                "X-MWS-Authentication header is blank, "
                "MCC-Authentication header is blank."
            )
        })

    def test_app_configuration_and_call_open_url(self):
        authenticator = FastAPIAuthenticator()
        authenticator.init_app(self.app)

        @self.app.get("/")
        async def root():
            return {"msg": "helloes"}

        client = TestClient(self.app)
        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "helloes"})

    def test_app_configuration_with_valid_call(self):
        authenticator = FastAPIAuthenticator()
        authenticator.init_app(self.app)
        f = Future()
        f.set_result((True, 200, ""))
        authenticator.authenticate = MagicMock(return_value=f)

        @self.app.get("/", dependencies=[Depends(requires_authentication)])
        async def root():
            return {"msg": "helloes"}

        client = TestClient(self.app)
        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "helloes"})
