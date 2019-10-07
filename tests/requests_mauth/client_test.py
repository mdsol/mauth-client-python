import unittest
import os
from requests import Request
from mauth_client.config import Config
from mauth_client.requests_mauth import MAuth

APP_UUID = "5ff4257e-9c16-11e0-b048-0026bbfffe5e"
URL = "https://innovate.imedidata.com/api/v2/users/10ac3b0e-9fe2-11df-a531-12313900d531/studies.json"

class RequestMock:
    """Simple mock for a request object"""
    def __init__(self, method, url, body):
        self.method = method
        self.url = url
        self.body = body


class MAuthBaseTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "keys", "test_mauth.priv.key"), "r") as key_file:
            self.example_private_key = key_file.read()

    def test_call(self):
        auth = MAuth(APP_UUID, self.example_private_key)
        request = Request("GET", URL, auth=auth).prepare()
        self.assertEqual(
            sorted(list(request.headers.keys())),
            ["Content-Type", "MCC-Authentication", "MCC-Time", "X-MWS-Authentication", "X-MWS-Time"]
        )

    def test_call_v2_only(self):
        auth = MAuth(APP_UUID, self.example_private_key, True)
        request = Request("GET", URL, auth=auth).prepare()
        self.assertEqual(
            sorted(list(request.headers.keys())),
            ["Content-Type", "MCC-Authentication", "MCC-Time"]
        )
