import unittest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocket
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import uuid4

from mauth_client.authenticator import LocalAuthenticator
from mauth_client.config import Config
from mauth_client.consts import (
    AUTH_HEADER_DELIMITER,
    X_MWS_AUTH,
    MWS_TOKEN,
    MCC_AUTH,
    MWSV2_TOKEN,
    ENV_APP_UUID,
    ENV_AUTHENTIC,
    ENV_PROTOCOL_VERSION,
)
from mauth_client.middlewares import MAuthASGIMiddleware


class TestMAuthASGIMiddlewareInitialization(unittest.TestCase):
    def setUp(self):
        self.app = FastAPI()
        Config.APP_UUID = str(uuid4())
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

    def test_app_configuration(self):
        try:
            self.app.add_middleware(MAuthASGIMiddleware)
            self.app.build_middleware_stack()
        except TypeError:
            self.fail("Shouldn't raise exception")

    def test_app_configuration_missing_uuid(self):
        Config.APP_UUID = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
            self.app.build_middleware_stack()
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires APP_UUID and PRIVATE_KEY"
        )

    def test_app_configuration_missing_key(self):
        Config.PRIVATE_KEY = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
            self.app.build_middleware_stack()
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires APP_UUID and PRIVATE_KEY"
        )

    def test_app_configuration_missing_url(self):
        Config.MAUTH_URL = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
            self.app.build_middleware_stack()
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION"
        )

    def test_app_configuration_missing_version(self):
        Config.MAUTH_API_VERSION = None
        with self.assertRaises(TypeError) as exc:
            self.app.add_middleware(MAuthASGIMiddleware)
            self.app.build_middleware_stack()
        self.assertEqual(
            str(exc.exception),
            "MAuthASGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION"
        )


class TestMAuthASGIMiddlewareFunctionality(unittest.TestCase):
    def setUp(self):
        self.app_uuid = str(uuid4())
        Config.APP_UUID = self.app_uuid
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

        self.app = FastAPI()
        self.app.add_middleware(MAuthASGIMiddleware, exempt={"/app_status"})

        @self.app.get("/")
        async def root():
            return {"msg": "authenticated"}

        @self.app.get("/app_status")
        async def app_status():
            return {"msg": "open"}

        self.client = TestClient(self.app)

    def test_401_reponse_when_not_authenticated(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {
            "errors": {
                "mauth": [(
                    "Authentication Failed. No mAuth signature present; "
                    "X-MWS-Authentication header is blank, "
                    "MCC-Authentication header is blank."
                )]
            }
        })

    def test_ok_when_calling_open_route(self):
        response = self.client.get("/app_status")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "open"})

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_ok_when_authenticated(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "authenticated"})

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_values_to_context_v1(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        headers_v1 = {
            X_MWS_AUTH: f"{MWS_TOKEN} {self.app_uuid}:blah"
        }

        @self.app.get("/v1_test")
        def root(request: Request):
            self.assertEqual(request.scope[ENV_APP_UUID], self.app_uuid)
            self.assertEqual(request.scope[ENV_AUTHENTIC], True)
            self.assertEqual(request.scope[ENV_PROTOCOL_VERSION], 1)
            return {"msg": "got it"}

        self.client.get("/v1_test", headers=headers_v1)

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_adds_values_to_context_v2(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")

        headers_v2 = {
            MCC_AUTH: f"{MWSV2_TOKEN} {self.app_uuid}:blah{AUTH_HEADER_DELIMITER}"
        }

        @self.app.get("/v2_test")
        def root(request: Request):
            self.assertEqual(request.scope[ENV_APP_UUID], self.app_uuid)
            self.assertEqual(request.scope[ENV_AUTHENTIC], True)
            self.assertEqual(request.scope[ENV_PROTOCOL_VERSION], 2)
            return {"msg": "got it"}

        self.client.get("/v2_test", headers=headers_v2)

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_downstream_can_receive_body(self, is_authentic_mock):
        is_authentic_mock.return_value = (True, 200, "")
        expected_body = {"msg": "test"}

        @self.app.post("/post_test")
        async def post_test(request: Request):
            body = await request.json()
            self.assertEqual(body, expected_body)
            return {"msg": "app can still read the body!"}

        self.client.post("/post_test", json=expected_body)

    def test_ignores_non_http_requests(self):
        @self.app.websocket_route("/ws")
        async def ws(websocket: WebSocket):
            await websocket.accept()
            await websocket.send_json({"msg": "helloes"})
            await websocket.close()

        with self.client.websocket_connect("/ws") as websocket:
            data = websocket.receive_json()
            self.assertEqual(data, {"msg": "helloes"})


class TestMAuthASGIMiddlewareInSubApplication(unittest.TestCase):
    def setUp(self):
        self.app_uuid = str(uuid4())
        Config.APP_UUID = self.app_uuid
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

        self.app = FastAPI()
        sub_app = FastAPI()
        sub_app.add_middleware(MAuthASGIMiddleware)

        @sub_app.get("/path")
        async def sub_app_path():
            return {"msg": "sub app path"}

        self.app.mount("/sub_app", sub_app)

        self.client = TestClient(self.app)

    @patch.object(LocalAuthenticator, "is_authentic", autospec=True)
    def test_includes_base_application_path_in_signature_verification(self, is_authentic_mock):
        request_url = None

        def is_authentic_effect(self):
            nonlocal request_url
            request_url = self.signable.attributes_for_signing["request_url"]
            return True, 200, ""

        is_authentic_mock.side_effect = is_authentic_effect

        self.client.get("/sub_app/path")

        self.assertEqual(request_url, "/sub_app/path")


class TestMAuthASGIMiddlewareInLongLivedConnections(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.app = FastAPI()
        Config.APP_UUID = str(uuid4())
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

    @patch.object(LocalAuthenticator, "is_authentic")
    async def test_fake_receive_delegates_to_original_after_body_consumed(self, is_authentic_mock):
        """Test that after body events are consumed, _fake_receive delegates to original receive"""
        is_authentic_mock.return_value = (True, 200, "")

        # Track that original receive was called after body events exhausted
        call_order = []

        async def mock_app(scope, receive, send):
            # First receive should get body event
            event1 = await receive()
            call_order.append(("body", event1["type"]))

            # Second receive should delegate to original receive
            event2 = await receive()
            call_order.append(("disconnect", event2["type"]))

            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = MAuthASGIMiddleware(mock_app)

        # Mock receive that returns body then disconnect
        receive_calls = 0

        async def mock_receive():
            nonlocal receive_calls
            receive_calls += 1
            if receive_calls == 1:
                return {"type": "http.request", "body": b"test", "more_body": False}
            return {"type": "http.disconnect"}

        send_mock = AsyncMock()
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/test",
            "query_string": b"",
            "headers": []
        }

        await middleware(scope, mock_receive, send_mock)

        # Verify events were received in correct order
        self.assertEqual(len(call_order), 2)
        self.assertEqual(call_order[0], ("body", "http.request"))
        self.assertEqual(call_order[1], ("disconnect", "http.disconnect"))
        self.assertEqual(receive_calls, 2)  # Called once for auth, once from app


class TestMAuthASGIMiddlewareWithPrefixMatch(unittest.TestCase):
    def setUp(self):
        self.app_uuid = str(uuid4())
        Config.APP_UUID = self.app_uuid
        Config.MAUTH_URL = "https://mauth.com"
        Config.MAUTH_API_VERSION = "v1"
        Config.PRIVATE_KEY = "key"

        self.app = FastAPI()
        self.app.add_middleware(
            MAuthASGIMiddleware,
            exempt={"/health", "/metrics"},
            exempt_prefix_match=True
        )

        @self.app.get("/")
        async def root():
            return {"msg": "authenticated"}

        @self.app.get("/health")
        async def health_exact():
            return {"msg": "exact health"}

        @self.app.get("/health/live")
        async def health_live():
            return {"msg": "health live"}

        @self.app.get("/health/ready")
        async def health_ready():
            return {"msg": "health ready"}

        @self.app.get("/metrics/prometheus")
        async def metrics():
            return {"msg": "metrics"}

        @self.app.get("/api/health")
        async def api_health():
            return {"msg": "api health"}

        self.client = TestClient(self.app)

    def test_prefix_match_allows_nested_paths(self):
        """Test that nested paths under exempt prefix are allowed"""
        response = self.client.get("/health/live")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "health live"})

        response = self.client.get("/health/ready")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "health ready"})

        response = self.client.get("/metrics/prometheus")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "metrics"})

    def test_prefix_match_blocks_similar_paths(self):
        """Test that similar but non-matching paths are still blocked"""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 401)

    def test_prefix_match_allows_exact_match_in_exempt_set(self):
        """Test that exact match in exempt set is allowed (from exact match check)"""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "exact health"})

    @patch.object(LocalAuthenticator, "is_authentic")
    def test_prefix_match_still_authenticates_non_exempt_paths(self, is_authentic_mock):
        """Test that non-exempt paths still require authentication"""
        is_authentic_mock.return_value = (True, 200, "")

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"msg": "authenticated"})
