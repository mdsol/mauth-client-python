# 1.10.0
- Add support for Python 3.14
- Remove Support for EOL Python 3.9
- Remove tox in favor of running pytest directly with Poetry and the GitHub Actions Python version matrix.

# 1.9.0
- Add support for PKCS#8 private key format

# 1.8.0
- Add `to_rsa_format` function to normalize private key
- Update requests_mauth and httpx_mauth to support reading configuration from environment variables

# 1.7.0
- Add `MAuthHttpx` custom authentication scheme for HTTPX.
- Remove Support for EOL Python 3.8

# 1.6.6
- Support long-lived connections in ASGI middleware

# 1.6.5
- Resolved dependabot identified security issues
- Removed build status icon from travis (not used for CI any longer)

# 1.6.4
- Fix `MAuthASGIMiddleware` when accessing `path` when `path` is not set yet.
  This appears to only happen on startup.
- Replace the character `\n` on one-liner private keys.

# 1.6.3
- Revert change introduced in v1.6.2 now that Starlette has been updated to
  always include `root_path` in `path`.

# 1.6.2
- Fix `MAuthASGIMiddleware` signature validation when the full URL path is split
  between `root_path` and `path` in the request scope.

# 1.6.1
- Fix `MAuthWSGIMiddleware` to return a string for "status" and to properly set
  content-length header.

# 1.6.0
- Fix bug with reading request body in `MAuthWSGIMiddleware`.
- Remove Support for EOL Python 3.7

# 1.5.1
- Fix `MAuthWSGIMiddleware` to no longer depend on `werkzeug` data in the request env.

# 1.5.0
- Replace `cchardet` with `charset-normalizer` to support Python 3.11

# 1.4.0
- Add `MAuthWSGIMiddleware` for authenticating requests in WSGI frameworks like Flask.
- Remove `FlaskAuthenticator`.

# 1.3.0
- Add `MAuthASGIMiddleware` for authenticating requests in ASGI frameworks like FastAPI.
- Remove Support for EOL Python 3.6

# 1.2.3
- Ignore `boto3` import error (`ModuleNotFoundError`).

# 1.2.2
- Extend the fallback cache TTL to 5 minutes.

# 1.2.1
- Add autodeploy to PyPI
- Remove Support for EOL Python 3.5
- Remove PyPy support

# 1.2.0
- Change the default signing versions (`MAUTH_SIGN_VERSIONS` option) to `v1` only.

# 1.1.0
- Replace `V2_ONLY_SIGN_REQUESTS` option with `MAUTH_SIGN_VERSIONS` option and change the default to `v2` only.

# 1.0.0
- Add parsing code to test with mauth-protocol-test-suite.
- Add unescape step in query_string encoding in order to remove "double encoding".
- Add normalization of paths.

# 0.5.0
- Fall back to V1 when V2 authentication fails.

# 0.4.0
- Add `FlaskAuthenticator` to authenticate requests in Flask applications.

# 0.3.0
- Support binary request bodies.

# 0.2.1
- Fix `LambdaAuthenticator` to return an empty string on "200 OK" response.

# 0.2.0
- Add support for MWSV2 protocol.
- Rename `MAuthAuthenticator` to `LambdaAuthenticator`.

# 0.1.0
- Initial release.
