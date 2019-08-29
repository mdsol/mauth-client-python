import cachetools
import os
import re
import requests
from requests.adapters import HTTPAdapter
from .lambda_helper import generate_mauth, create_x_b3_headers
from .exceptions import InauthenticError

CACHE_MAXSIZE = 128
CACHE_TTL = 60
MAX_AGE_REGEX = re.compile('max-age=(\d+)')

class KeyHolder(object):
    _CACHE = None
    _MAUTH = None
    _MAUTH_URL = None
    _MAX_RETRIES = 3

    @classmethod
    def get_public_key(cls, app_uuid, trace_id):
        if not cls._CACHE or not app_uuid in cls._CACHE:
            cls._set_public_key(app_uuid, trace_id)

        return cls._CACHE.get(app_uuid)

    @classmethod
    def _set_public_key(cls, app_uuid, trace_id):
        public_key, cache_control = cls._get_public_key_and_cache_control_from_mauth(app_uuid, trace_id)
        if not cls._CACHE:
            cls._CACHE = cls._create_cache(cache_control)

        cls._CACHE[app_uuid] = public_key

    @classmethod
    def _create_cache(cls, cache_control):
        max_age_match = MAX_AGE_REGEX.match(cache_control or '')
        ttl = int(max_age_match.group(1)) if max_age_match else CACHE_TTL
        return cachetools.TTLCache(maxsize=CACHE_MAXSIZE, ttl=ttl)

    @classmethod
    def _get_public_key_and_cache_control_from_mauth(cls, app_uuid, trace_id):
        if not cls._MAUTH:
            cls._MAUTH = generate_mauth()
        if not cls._MAUTH_URL:
            cls._MAUTH_URL = os.environ['MAUTH_URL']

        url = f'{cls._MAUTH_URL}/mauth/v1/security_tokens/{app_uuid}.json'
        response = cls._request_session().get(url, auth=cls._MAUTH, headers=create_x_b3_headers(trace_id))
        if response.status_code == 200:
            return response.json().get('security_token').get('public_key_str'), response.headers.get('Cache-Control')
        else:
            raise InauthenticError(f'Failed to fetch the public key for {app_uuid} from {cls._MAUTH_URL}')

    @classmethod
    def _request_session(cls):
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=cls._MAX_RETRIES)
        session.mount('https://', adapter)
        return session
