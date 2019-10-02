import unittest
import json
from hashlib import sha512
from mauth_client.signable import RequestSignable
from mauth_client.exceptions import UnableToSignError

APP_UUID = "5ff4257e-9c16-11e0-b048-0026bbfffe5e"
REQUEST_ATTRIBUTES = {
    "method": "GET",
    "url": "https://example.org/studies/123/users?k=v"
}


class RequestSignableTest(unittest.TestCase):
    def setUp(self):
        self.request_signable = RequestSignable(**REQUEST_ATTRIBUTES)

    def test_string_to_sign_v1(self):
        expected = "GET" + "\n" \
            "/studies/123/users" + "\n" \
            "\n" \
            "5ff4257e-9c16-11e0-b048-0026bbfffe5e" + "\n" \
            "1309891855"

        epoch = 1309891855
        tested = self.request_signable.string_to_sign_v1({ "app_uuid": APP_UUID, "time": epoch })
        self.assertEqual(tested, expected)

    def test_string_to_sign_v1_missing_attributes(self):
        with self.assertRaises(UnableToSignError) as exc:
            RequestSignable(**{}).string_to_sign_v1({})
        self.assertEqual(str(exc.exception),
                         "Missing required attributes to sign: ['verb', 'request_url', 'app_uuid', 'time']")

    def test_string_to_sign_v2(self):
        expected = "GET" + "\n" \
            "/studies/123/users" + "\n" \
            + sha512("".encode()).hexdigest() + "\n" \
            "5ff4257e-9c16-11e0-b048-0026bbfffe5e" + "\n" \
            "1309891855" + "\n" \
            "k=v"

        epoch = 1309891855
        tested = self.request_signable.string_to_sign_v2({ "app_uuid": APP_UUID, "time": epoch })
        self.assertEqual(tested, expected)

    def test_string_to_sign_v2_missing_attributes(self):
        with self.assertRaises(UnableToSignError) as exc:
            RequestSignable(**{}).string_to_sign_v2({})
        self.assertEqual(str(exc.exception),
                         "Missing required attributes to sign: ['verb', 'request_url', 'app_uuid', 'time']")

    def test_encode_query_string_special_characters(self):
        query_string = "key=-_.~ !@#$%^*()+{}|:\"'`<>?"
        expected = "key=-_.~%20%21%40%23%24%25%5E%2A%28%29%2B%7B%7D%7C%3A%22%27%60%3C%3E%3F"
        self.assertEqual(self.request_signable.encode_query_string(query_string), expected)

    def test_encode_query_string_sort_by_code_point(self):
        query_string = "∞=v&キ=v&0=v&a=v"
        expected = "0=v&a=v&%E2%88%9E=v&%E3%82%AD=v"
        self.assertEqual(self.request_signable.encode_query_string(query_string), expected)

    def test_encode_query_string_sort_by_value_if_keys_are_the_same(self):
        query_string = "a=b&a=c&a=a"
        expected = "a=a&a=b&a=c"
        self.assertEqual(self.request_signable.encode_query_string(query_string), expected)

    def test_encode_query_string_empty_values(self):
        query_string = "k=&k=v"
        self.assertEqual(self.request_signable.encode_query_string(query_string), query_string)

    def test_encode_query_string_empty_string(self):
        self.assertEqual(self.request_signable.encode_query_string(""), "")

    def test_build_attributes_binary_body(self):
        expected = {
            "verb": "GET",
            "request_url": "/studies/123/users",
            "query_string": "",
            "body": '{"key": "data"}'
        }
        url = "https://innovate.imedidata.com/studies/123/users"
        binary_body = json.dumps( { "key": "data" } ).encode("utf8")
        tested = self.request_signable.build_attributes(method="GET", url=url, body=binary_body)
        self.assertEqual(tested, expected)
