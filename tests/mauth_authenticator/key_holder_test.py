import json
import sys
from io import StringIO

import unittest
from unittest.mock import MagicMock

import requests_mock
from mauth_client.mauth_authenticator.key_holder import KeyHolder
from mauth_client.mauth_authenticator.exceptions import InauthenticError
from tests.mauth_authenticator.common import load_key

APP_UUID = 'f5af50b2-bf7d-4c29-81db-76d086d4808a'
MAUTH_URL = 'https://mauth.com'
MAUTH_PATH = '{}/mauth/v1/security_tokens/{}.json'.format(MAUTH_URL, APP_UUID)
PUBLIC_KEY = load_key('rsapub')

MAUTH_RESPONSE = {
    'security_token': {
        'app_name': 'awesome-app-sandbox',
        'app_uuid': APP_UUID,
        'public_key_str': PUBLIC_KEY,
        'created_at': '2016-10-21T21:16:14Z'
    }
}

CACHE_CONTROL = 'max-age=60, private'

class TestKeyHolder(unittest.TestCase):
    def setUp(self):
        KeyHolder._MAUTH = MagicMock()
        KeyHolder._MAUTH_URL = MAUTH_URL

        # redirect the output of stdout to self.captor
        self.captor = StringIO()
        sys.stdout = self.captor

    def tearDown(self):
        # reset the output of stdout to console
        sys.stdout = sys.__stdout__

    def test_get_request(self):
        KeyHolder._CACHE = None
        with requests_mock.mock() as requests:
            requests.get(MAUTH_PATH, text=json.dumps(MAUTH_RESPONSE))
            self.assertEqual(KeyHolder.get_public_key(APP_UUID), PUBLIC_KEY)
            self.assertEqual(KeyHolder._CACHE.maxsize, 128)
            self.assertEqual(KeyHolder._CACHE.ttl, 60)

    def test_get_request_respect_cache_header(self):
        KeyHolder._CACHE = None
        with requests_mock.mock() as requests:
            requests.get(MAUTH_PATH, text=json.dumps(MAUTH_RESPONSE), headers={'Cache-Control': CACHE_CONTROL})
            self.assertEqual(KeyHolder.get_public_key(APP_UUID), PUBLIC_KEY)
            self.assertEqual(KeyHolder._CACHE.ttl, 60)

    def test_get_request_cache_expiration(self):
        KeyHolder._CACHE = None
        with requests_mock.mock() as requests:
            requests.get(MAUTH_PATH, text=json.dumps(MAUTH_RESPONSE), headers={'Cache-Control': CACHE_CONTROL})
            self.assertEqual(KeyHolder.get_public_key(APP_UUID), PUBLIC_KEY)
            KeyHolder._CACHE.expire(KeyHolder._CACHE.timer() + 60)
            self.assertEqual(KeyHolder._CACHE.get(APP_UUID), None)

    def test_get_request_404_error(self):
        KeyHolder._CACHE = None
        with requests_mock.mock() as requests:
            requests.get(MAUTH_PATH, status_code=404)
            with self.assertRaises(InauthenticError) as exc:
                KeyHolder.get_public_key(APP_UUID)
            self.assertEqual(
                str(exc.exception),
                'Failed to fetch the public key for {} from {}'.format(APP_UUID, MAUTH_URL)
            )
