import unittest
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocket
from uuid import uuid4

from mauth_client.authenticator import LocalAuthenticator
from mauth_client.config import Config
from mauth_client.consts import (
    AUTH_HEADER_DELIMITER,
    X_MWS_AUTH,
    MWS_TOKEN,
    MCC_AUTH,
    MWSV2_TOKEN,
    ENV_APP_UUID,
    ENV_AUTHENTIC,
    ENV_PROTOCOL_VERSION,
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
        self.app.add_middleware(MAuthASGIMiddleware, exempt={"/app_status"})

        @self.app.get("/")
        async def root():
            return {"msg": "authenticated"}

        @self.app.get("/app_status")
        async def app_status():
            return {"msg": "open"}

        self.client = TestClient(self.app)

    def test_401_reponse_when_not_authenticated(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {
            "errors": {
                "mauth": [(
                    "Authentication Failed. No mAuth signature present; "
                    "X-MWS-Authentication header is blank, "
                    "MCC-Authentication header is blank."
                )]
            }
        })

    def test_ok_when_calling_open_route(self):
        response = self.client.get("/app_status")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "open"})

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_ok_when_authenticated(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "authenticated"})

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_values_to_context_v1(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        headers_v1 = {
            X_MWS_AUTH: f"{MWS_TOKEN} {self.app_uuid}:blah"
        }

        @self.app.get("/v1_test")
        def root(request: Request):
            self.assertEqual(request.scope[ENV_APP_UUID], self.app_uuid)
            self.assertEqual(request.scope[ENV_AUTHENTIC], True)
            self.assertEqual(request.scope[ENV_PROTOCOL_VERSION], 1)
            return {"msg": "got it"}

        self.client.get("/v1_test", headers=headers_v1)

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_values_to_context_v2(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        headers_v2 = {
            MCC_AUTH: f"{MWSV2_TOKEN} {self.app_uuid}:blah{AUTH_HEADER_DELIMITER}"
        }

        @self.app.get("/v2_test")
        def root(request: Request):
            self.assertEqual(request.scope[ENV_APP_UUID], self.app_uuid)
            self.assertEqual(request.scope[ENV_AUTHENTIC], True)
            self.assertEqual(request.scope[ENV_PROTOCOL_VERSION], 2)
            return {"msg": "got it"}

        self.client.get("/v2_test", headers=headers_v2)

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_downstream_can_receive_body(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")
        expected_body = {"msg": "test"}

        @self.app.post("/post_test")
        async def post_test(request: Request):
            body = await request.json()
            self.assertEqual(body, expected_body)
            return {"msg": "app can still read the body!"}

        self.client.post("/post_test", json=expected_body)

    def test_ignores_non_http_requests(self):
        @self.app.websocket_route("/ws")
        async def ws(websocket: WebSocket):
            await websocket.accept()
            await websocket.send_json({"msg": "helloes"})
            await websocket.close()

        with self.client.websocket_connect("/ws") as websocket:
            data = websocket.receive_json()
            self.assertEqual(data, {"msg": "helloes"})
