import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from uuid import uuid4

from mauth_client.config import Config
from mauth_client.middlewares import MAuthASGIMiddleware


class TestMAuthASGIMiddlewareConfigs(unittest.TestCase):
    def setUp(self):
        self.app = FastAPI()
        Config.APP_UUID = str(uuid4())
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

    def test_app_configuration(self):
        try:
            self.app.add_middleware(MAuthASGIMiddleware)
        except TypeError:
            self.fail("Shouldn't raise exception")

    def test_app_configuration_missing_uuid(self):
        Config.APP_UUID = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires APP_UUID and PRIVATE_KEY"
        )

    def test_app_configuration_missing_key(self):
        Config.PRIVATE_KEY = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires APP_UUID and PRIVATE_KEY"
        )

    def test_app_configuration_missing_url(self):
        Config.MAUTH_URL = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION"
        )

    def test_app_configuration_missing_version(self):
        Config.MAUTH_API_VERSION = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION"
        )


class TestMAuthASGIMiddlewareFunctionality(unittest.TestCase):
    def setUp(self):
        Config.APP_UUID = str(uuid4())
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

        self.app = FastAPI()
        self.protected_app = FastAPI()

        @self.app.get("/")
        def root():
            return {"msg": "helloes"}

        self.protected_app.add_middleware(MAuthASGIMiddleware)

        @self.protected_app.get("/")
        def protected():
            return {"msg": "protected"}

        self.app.mount("/protected", self.protected_app)

    def test_401_reponse_when_not_authenticated(self):
        client = TestClient(self.app)
        response = client.get("/protected")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {
            "errors": {
                "mauth": (
                    "Authentication Failed. No mAuth signature present; "
                    "X-MWS-Authentication header is blank, "
                    "MCC-Authentication header is blank."
                )
            }
        })
