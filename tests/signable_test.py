import unittest
import json
from hashlib import sha512
from mauth_client.signable import RequestSignable
from mauth_client.exceptions import UnableToSignError

APP_UUID = "5ff4257e-9c16-11e0-b048-0026bbfffe5e"
REQUEST_ATTRIBUTES = {"method": "GET", "url": "https://example.org/studies/123/users?k=v"}


class RequestSignableTest(unittest.TestCase):
    def setUp(self):
        self.request_signable = RequestSignable(**REQUEST_ATTRIBUTES)

    def test_string_to_sign_v1(self):
        expected = (
            "GET" + "\n" "/studies/123/users" + "\n" "\n" "5ff4257e-9c16-11e0-b048-0026bbfffe5e" + "\n" "1309891855"
        )

        epoch = 1309891855
        tested = self.request_signable.string_to_sign_v1({"app_uuid": APP_UUID, "time": epoch}).decode("utf-8")
        self.assertEqual(tested, expected)

    def test_string_to_sign_v1_missing_attributes(self):
        with self.assertRaises(UnableToSignError) as exc:
            RequestSignable(**{}).string_to_sign_v1({})
        self.assertEqual(
            str(exc.exception), "Missing required attributes to sign: ['verb', 'request_url', 'app_uuid', 'time']"
        )

    def test_string_to_sign_v2(self):
        expected = (
            "GET" + "\n"
            "/studies/123/users" + "\n" + sha512("".encode()).hexdigest() + "\n"
            "5ff4257e-9c16-11e0-b048-0026bbfffe5e" + "\n"
            "1309891855" + "\n"
            "k=v"
        )

        epoch = 1309891855
        tested = self.request_signable.string_to_sign_v2({"app_uuid": APP_UUID, "time": epoch}).decode("utf-8")
        self.assertEqual(tested, expected)

    def test_string_to_sign_v2_missing_attributes(self):
        with self.assertRaises(UnableToSignError) as exc:
            RequestSignable(**{}).string_to_sign_v2({})
        self.assertEqual(
            str(exc.exception), "Missing required attributes to sign: ['verb', 'request_url', 'app_uuid', 'time']"
        )

    def test_encode_query_string(self):
        cases = {
            "special_characters_in_the_query_string_before_encoding_them": [
                "key=-_.%21%40%23%24%25%5E%2A%28%29%20%7B%7D%7C%3A%22%27%60%3C%3E%3F",
                "key=-_.%21%40%23%24%25%5E%2A%28%29%20%7B%7D%7C%3A%22%27%60%3C%3E%3F",
            ],
            "sort_by_value_if_keys_are_the_same": ["a=b&a=c&a=a", "a=a&a=b&a=c"],
            "sort_after_unescaping": ["k=%7E&k=~&k=%40&k=a", "k=%40&k=a&k=~&k=~"],
            "unescapes_tilda": ["k=%7E", "k=~"],
            "unescapes_plus": ["k=+", "k=%20"],
            "empty_values": ["k=&k=v", "k=&k=v"],
            "empty_string": ["", ""],
        }

        for case_name, case_item in cases.items():
            with self.subTest(case_name=case_name):
                self.assertEqual(self.request_signable.encode_query_string(case_item[0]), case_item[1])

    def test_build_attributes_binary_body(self):
        expected = {"verb": "GET", "request_url": "/studies/123/users", "query_string": "", "body": b'{"key": "data"}'}
        url = "https://innovate.imedidata.com/studies/123/users"
        binary_body = json.dumps({"key": "data"}).encode("utf8")
        tested = self.request_signable.build_attributes(method="GET", url=url, body=binary_body)
        self.assertEqual(tested, expected)

    def test_normalize_path(self):
        cases = {
            "self ('.'') in the path": ["/./example/./.", "/example/"],
            "parent ('..'') in path": ["/example/sample/..", "/example/"],
            "parent ('..') that points to non-existent parent": ["/example/sample/../../../..", "/"],
            "case of percent encoded characters": ["/%2b", "/%2B"],
            "multiple adjacent slashes to a single slash": ["//example///sample", "/example/sample"],
            "preserves trailing slashes": ["/example/", "/example/"],
        }

        for case_name, case_item in cases.items():
            with self.subTest(case_name=case_name):
                self.assertEqual(self.request_signable.normalize_path(case_item[0]), case_item[1])
