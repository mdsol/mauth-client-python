import json
import unittest
from unittest.mock import MagicMock

from flask import Flask

from mauth_client.config import Config
from mauth_client.flask_authenticator import FlaskAuthenticator, requires_authentication


class TestFlaskAuthenticator(unittest.TestCase):
    def setUp(self):
        self.app = Flask("Test App")
        Config.APP_UUID = "2f746447-c212-483c-9eec-d9b0216f7613"
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.MAUTH_MODE = "local"
        Config.PRIVATE_KEY = "key"

    def test_app_configuration(self):
        try:
            FlaskAuthenticator(self.app)
        except TypeError:
            self.fail("Shouldn't raise an exception")

    def test_app_configuration_missing_uuid(self):
        Config.APP_UUID = None
        with self.assertRaises(TypeError) as exc:
            FlaskAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FlaskAuthenticator requires APP_UUID and PRIVATE_KEY")

    def test_app_configuration_missing_key(self):
        Config.PRIVATE_KEY = None
        with self.assertRaises(TypeError) as exc:
            FlaskAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FlaskAuthenticator requires APP_UUID and PRIVATE_KEY")

    def test_app_configuration_missing_base_url(self):
        Config.MAUTH_URL = None
        with self.assertRaises(TypeError) as exc:
            FlaskAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FlaskAuthenticator requires MAUTH_URL and MAUTH_API_VERSION")

    def test_app_configuration_missing_version(self):
        Config.MAUTH_API_VERSION = None
        with self.assertRaises(TypeError) as exc:
            FlaskAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FlaskAuthenticator requires MAUTH_URL and MAUTH_API_VERSION")

    def test_app_configuration_wrong_mode(self):
        Config.MAUTH_MODE = "banana"
        with self.assertRaises(TypeError) as exc:
            FlaskAuthenticator(self.app)
        self.assertEqual(str(exc.exception), "FlaskAuthenticator MAUTH_MODE must be one of local or remote")

    def test_app_configuration_remote(self):
        Config.MAUTH_MODE = "remote"
        try:
            FlaskAuthenticator(self.app)
        except TypeError:
            self.fail("Shouldn't raise an exception")

    def test_app_configuration_and_call_protected_url(self):
        authenticator = FlaskAuthenticator()
        authenticator.init_app(self.app)

        @self.app.route("/", methods=["GET"])
        @requires_authentication
        def test_url_closed():
            return "Ping"

        client = self.app.test_client()

        # protected URL
        response = client.get("/")
        self.assertEqual(401, response.status_code)
        self.assertEqual(dict(errors=dict(mauth=["Authentication Failed. No mAuth signature present; "
                                                 "X-MWS-Authentication header is blank, "
                                                 "MCC-Authentication header is blank."])),
                         json.loads(response.data.decode("utf-8")))

    def test_app_configuration_and_call_open_url(self):
        authenticator = FlaskAuthenticator()
        authenticator.init_app(self.app)

        @self.app.route("/lemon", methods=["GET"])
        def test_url_open():
            return "Ping"

        client = self.app.test_client()

        # open URL
        response = client.get("/lemon")
        self.assertEqual(200, response.status_code)
        self.assertEqual(b"Ping", response.data)

    def test_app_configuration_with_valid_call(self):
        @self.app.route("/", methods=["GET"])
        @requires_authentication
        def test_url_closed():
            return "Ping"

        client = self.app.test_client()

        authenticator = FlaskAuthenticator()
        authenticator.init_app(self.app)
        authenticator.authenticate = MagicMock(return_value=(True, 200, ""))
        # protected URL
        response = client.get("/")
        self.assertEqual(200, response.status_code)
        self.assertEqual(b"Ping", response.data)
