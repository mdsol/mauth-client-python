import unittest
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from uuid import uuid4

from mauth_client.authenticator import LocalAuthenticator
from mauth_client.config import Config
from mauth_client.consts import (
    AUTH_HEADER_DELIMITER, X_MWS_AUTH, MWS_TOKEN, MCC_AUTH, MWSV2_TOKEN
)
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
        self.app_uuid = str(uuid4())
        Config.APP_UUID = self.app_uuid
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
        self.client = TestClient(self.app)

    def test_401_reponse_when_not_authenticated(self):
        response = self.client.get("/protected")

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

    def test_ok_when_calling_unprotected_route(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "helloes"})

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_ok_when_authenticated(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        response = self.client.get("/protected")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "protected"})

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_app_uuid_to_context_v1(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        app = FastAPI()
        app.add_middleware(MAuthASGIMiddleware)

        app_uuid = str(uuid4())
        headers_v1 = {
            X_MWS_AUTH: f"{MWS_TOKEN} {app_uuid}:blah"
        }

        @app.get("/")
        def root(request: Request):
            self.assertEqual(request.scope["mauth"]["app_uuid"], app_uuid)
            return {"msg": "got it"}

        client = TestClient(app)
        client.get("/", headers=headers_v1)

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_app_uuid_to_context_v2(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        app = FastAPI()
        app.add_middleware(MAuthASGIMiddleware)

        app_uuid = str(uuid4())
        headers_v2 = {
            MCC_AUTH: f"{MWSV2_TOKEN} {app_uuid}:blah{AUTH_HEADER_DELIMITER}"
        }

        @app.get("/")
        def root(request: Request):
            self.assertEqual(request.scope["mauth"]["app_uuid"], app_uuid)
            return {"msg": "got it"}

        client = TestClient(app)
        client.get("/", headers=headers_v2)
