import unittest
from unittest.mock import MagicMock

from fastapi import FastAPI

from mauth_client.config import Config
from mauth_client.fastapi_authenticator import requires_authentication


class TestFastAPIAuthenticator(unittest.TestCase):
    def setUp(self) -> None:
        self.app = FastAPI()
        Config.APP_UUID = "2f746447-c212-483c-9eec-d9b0216f7613"
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.MAUTH_MODE = "local"
        Config.PRIVATE_KEY = "key"
