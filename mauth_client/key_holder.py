import cachetools
import re
import requests
from requests.adapters import HTTPAdapter
from mauth_client.config import Config
from mauth_client.lambda_helper import generate_mauth
from mauth_client.exceptions import InauthenticError

CACHE_MAXSIZE = 128
CACHE_TTL = 60
MAX_AGE_REGEX = re.compile(r"max-age=(\d+)")


class KeyHolder:
    _CACHE = None
    _MAUTH = None
    _MAX_RETRIES = 3

    @classmethod
    def get_public_key(cls, app_uuid):
        if not cls._CACHE or app_uuid not in cls._CACHE:
            cls._set_public_key(app_uuid)

        return cls._CACHE.get(app_uuid)

    @classmethod
    def _set_public_key(cls, app_uuid):
        public_key, cache_control = cls._get_public_key_and_cache_control_from_mauth(app_uuid)
        if not cls._CACHE:
            cls._CACHE = cls._create_cache(cache_control)

        cls._CACHE[app_uuid] = public_key

    @classmethod
    def _create_cache(cls, cache_control):
        max_age_match = MAX_AGE_REGEX.match(cache_control or "")
        ttl = int(max_age_match.group(1)) if max_age_match else CACHE_TTL
        return cachetools.TTLCache(maxsize=CACHE_MAXSIZE, ttl=ttl)

    @classmethod
    def _get_public_key_and_cache_control_from_mauth(cls, app_uuid):
        if not cls._MAUTH:
            cls._MAUTH = {"auth": generate_mauth(), "url": Config.MAUTH_URL, "api_version": Config.MAUTH_API_VERSION}

        url = "{}/mauth/{}/security_tokens/{}.json".format(cls._MAUTH["url"], cls._MAUTH["api_version"], app_uuid)
        response = cls._request_session().get(url, auth=cls._MAUTH["auth"])
        if response.status_code == 200:
            return response.json().get("security_token").get("public_key_str"), response.headers.get("Cache-Control")

        raise InauthenticError("Failed to fetch the public key for {} from {}".format(app_uuid, cls._MAUTH["url"]))

    @classmethod
    def _request_session(cls):
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=cls._MAX_RETRIES)
        session.mount("https://", adapter)
        return session
