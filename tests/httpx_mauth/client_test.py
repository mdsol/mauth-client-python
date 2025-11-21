import unittest
import os
import httpx
from mauth_client.httpx_mauth import MAuthHttpx

APP_UUID = "5ff4257e-9c16-11e0-b048-0026bbfffe5e"
URL = "https://innovate.imedidata.com/api/v2/users/10ac3b0e-9fe2-11df-a531-12313900d531/studies.json"


def handler(request):
    return httpx.Response(200, json={"text": "Hello, world!"})


class MAuthHttpxBaseTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "keys", "fake_mauth.priv.key"), "r") as key_file:
            self.example_private_key = key_file.read()

    def test_call(self):
        auth = MAuthHttpx(APP_UUID, self.example_private_key, sign_versions="v1,v2")
        with httpx.Client(transport=httpx.MockTransport(handler), auth=auth) as client:
            response = client.get(URL)

        for header in ["mcc-authentication", "mcc-time", "x-mws-authentication", "x-mws-time"]:
            self.assertIn(header, response.request.headers)

    def test_call_v1_only(self):
        auth = MAuthHttpx(APP_UUID, self.example_private_key)
        with httpx.Client(transport=httpx.MockTransport(handler), auth=auth) as client:
            response = client.get(URL)

        for header in ["x-mws-authentication", "x-mws-time"]:
            self.assertIn(header, response.request.headers)

    def test_call_v2_only(self):
        auth = MAuthHttpx(APP_UUID, self.example_private_key, sign_versions="v2")
        with httpx.Client(transport=httpx.MockTransport(handler), auth=auth) as client:
            response = client.get(URL)

        for header in ["mcc-authentication", "mcc-time"]:
            self.assertIn(header, response.request.headers)
