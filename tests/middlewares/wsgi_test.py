import json
import unittest
from unittest.mock import patch

from flask import Flask, request, jsonify
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
from mauth_client.middlewares import MAuthWSGIMiddleware


class TestMAuthWSGIMiddlewareInitialization(unittest.TestCase):
    def setUp(self):
        self.app = Flask("Test App")
        Config.APP_UUID = "2f746447-c212-483c-9eec-d9b0216f7613"
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

    def test_app_configuration(self):
        try:
            self.app.wsgi_app = MAuthWSGIMiddleware(self.app)
        except TypeError:
            self.fail("Shouldn't raise exception")

    def test_app_configuration_missing_uuid(self):
        Config.APP_UUID = None
        with self.assertRaises(TypeError) as exc:
            self.app.wsgi_app = MAuthWSGIMiddleware(self.app)
        self.assertEqual(
            str(exc.exception),
            "MAuthWSGIMiddleware requires APP_UUID and PRIVATE_KEY"
        )

    def test_app_configuration_missing_key(self):
        Config.PRIVATE_KEY = None
        with self.assertRaises(TypeError) as exc:
            self.app.wsgi_app = MAuthWSGIMiddleware(self.app)
        self.assertEqual(
            str(exc.exception),
            "MAuthWSGIMiddleware requires APP_UUID and PRIVATE_KEY"
        )

    def test_app_configuration_missing_url(self):
        Config.MAUTH_URL = None
        with self.assertRaises(TypeError) as exc:
            self.app.wsgi_app = MAuthWSGIMiddleware(self.app)
        self.assertEqual(
            str(exc.exception),
            "MAuthWSGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION"
        )

    def test_app_configuration_missing_version(self):
        Config.MAUTH_API_VERSION = None
        with self.assertRaises(TypeError) as exc:
            self.app.wsgi_app = MAuthWSGIMiddleware(self.app)
        self.assertEqual(
            str(exc.exception),
            "MAuthWSGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION"
        )


class TestMAuthWSGIMiddlewareFunctionality(unittest.TestCase):
    def setUp(self):
        self.app_uuid = str(uuid4())
        Config.APP_UUID = self.app_uuid
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

        self.app = Flask("Test App")
        self.app.wsgi_app = MAuthWSGIMiddleware(
            self.app.wsgi_app,
            exempt={"/app_status"},
        )

        @self.app.get("/")
        def root():
            return "authenticated!"

        @self.app.get("/app_status")
        def app_status():
            return "open"

        self.client = self.app.test_client()

    def test_401_response_when_not_authenticated(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json, {
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
        self.assertEqual(response.get_data(as_text=True), "open")

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_ok_when_authenticated(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "authenticated!")

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_values_to_context_v1(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        headers_v1 = {
            X_MWS_AUTH: f"{MWS_TOKEN} {self.app_uuid}:blah"
        }

        @self.app.get("/v1_test")
        def v1_test():
            return jsonify({
                "app_uuid": request.environ[ENV_APP_UUID],
                "authentic": request.environ[ENV_AUTHENTIC],
                "protocol": request.environ[ENV_PROTOCOL_VERSION],
            })

        response = self.client.get("/v1_test", headers=headers_v1)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {
            "app_uuid": self.app_uuid,
            "authentic": True,
            "protocol": 1,
        })

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_values_to_context_v2(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        headers_v2 = {
            MCC_AUTH: f"{MWSV2_TOKEN} {self.app_uuid}:blah{AUTH_HEADER_DELIMITER}"
        }

        @self.app.get("/v2_test")
        def v2_test():
            return jsonify({
                "app_uuid": request.environ[ENV_APP_UUID],
                "authentic": request.environ[ENV_AUTHENTIC],
                "protocol": request.environ[ENV_PROTOCOL_VERSION],
            })

        response = self.client.get("/v2_test", headers=headers_v2)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {
            "app_uuid": self.app_uuid,
            "authentic": True,
            "protocol": 2,
        })

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_downstream_can_receive_body(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")
        body = {"msg": "helloes"}

        @self.app.post("/post_test")
        def post_test():
            return jsonify(request.json)

        response = self.client.post(
            "/post_test",
            data=json.dumps(body),
            headers={"content-type": "application/json"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, body)
