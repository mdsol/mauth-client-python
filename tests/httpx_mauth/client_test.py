import unittest
import httpx
from mauth_client.httpx_mauth import MAuthHttpx
from ..common import load_key

APP_UUID = "5ff4257e-9c16-11e0-b048-0026bbfffe5e"
PRIVATE_KEY = load_key("priv")
URL = "https://innovate.imedidata.com/api/v2/users/10ac3b0e-9fe2-11df-a531-12313900d531/studies.json"


def handler(request):
    return httpx.Response(200, json={"text": "Hello, world!"})


class MAuthHttpxBaseTest(unittest.TestCase):
    def test_call(self):
        auth = MAuthHttpx(APP_UUID, PRIVATE_KEY, sign_versions="v1,v2")
        with httpx.Client(transport=httpx.MockTransport(handler), auth=auth) as client:
            response = client.get(URL)

        for header in ["mcc-authentication", "mcc-time", "x-mws-authentication", "x-mws-time"]:
            self.assertIn(header, response.request.headers)

    def test_call_v1_only(self):
        auth = MAuthHttpx(APP_UUID, PRIVATE_KEY)
        with httpx.Client(transport=httpx.MockTransport(handler), auth=auth) as client:
            response = client.get(URL)

        for header in ["x-mws-authentication", "x-mws-time"]:
            self.assertIn(header, response.request.headers)

    def test_call_v2_only(self):
        auth = MAuthHttpx(APP_UUID, PRIVATE_KEY, sign_versions="v2")
        with httpx.Client(transport=httpx.MockTransport(handler), auth=auth) as client:
            response = client.get(URL)

        for header in ["mcc-authentication", "mcc-time"]:
            self.assertIn(header, response.request.headers)
