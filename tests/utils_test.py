import unittest
from mauth_client.utils import is_exempt_request_path


class TestIsExemptRequestPath(unittest.TestCase):
    """Test the is_exempt_request_path utility function."""

    def test_exact_prefix_match_with_trailing_slash(self):
        """Test that paths with trailing slashes in exempt set match correctly."""
        exempt = {"/health/"}
        self.assertTrue(is_exempt_request_path("/health/check", exempt))
        self.assertTrue(is_exempt_request_path("/health/status", exempt))

    def test_exact_prefix_match_without_trailing_slash(self):
        """Test that paths without trailing slashes in exempt set match correctly."""
        exempt = {"/health"}
        self.assertTrue(is_exempt_request_path("/health/check", exempt))
        self.assertTrue(is_exempt_request_path("/health/status", exempt))

    def test_no_match_similar_prefix(self):
        """Test that similar but non-matching paths return False."""
        exempt = {"/api"}
        self.assertFalse(is_exempt_request_path("/api-admin", exempt))
        self.assertFalse(is_exempt_request_path("/api-v2", exempt))
        self.assertFalse(is_exempt_request_path("/apis", exempt))

    def test_no_match_similar_prefix_with_underscore(self):
        """Test prevention of false matches with underscores."""
        exempt = {"/app_status"}
        self.assertFalse(is_exempt_request_path("/app_status_admin", exempt))
        self.assertFalse(is_exempt_request_path("/app_status_internal", exempt))

    def test_nested_path_match(self):
        """Test deeply nested paths under exempt prefix."""
        exempt = {"/api"}
        self.assertTrue(is_exempt_request_path("/api/v1/users", exempt))
        self.assertTrue(is_exempt_request_path("/api/v2/products/123", exempt))

    def test_exact_match_path_returns_false(self):
        """Test that exact match of exempt path without trailing slash returns False."""
        exempt = {"/health"}
        # This is by design - the function checks for prefix with '/'
        self.assertFalse(is_exempt_request_path("/health", exempt))

    def test_exact_match_with_trailing_slash_in_path(self):
        """Test exact match when request path has trailing slash."""
        exempt = {"/health"}
        self.assertTrue(is_exempt_request_path("/health/", exempt))

    def test_multiple_exempt_paths(self):
        """Test with multiple exempt paths."""
        exempt = {"/health", "/metrics", "/status"}
        self.assertTrue(is_exempt_request_path("/health/check", exempt))
        self.assertTrue(is_exempt_request_path("/metrics/prometheus", exempt))
        self.assertTrue(is_exempt_request_path("/status/ready", exempt))
        self.assertFalse(is_exempt_request_path("/api/users", exempt))

    def test_empty_exempt_set(self):
        """Test with empty exempt set returns False."""
        exempt = set()
        self.assertFalse(is_exempt_request_path("/any/path", exempt))
        self.assertFalse(is_exempt_request_path("/", exempt))

    def test_root_path_exempt(self):
        """Test root path exemption."""
        exempt = {"/"}
        self.assertTrue(is_exempt_request_path("/anything", exempt))
        self.assertTrue(is_exempt_request_path("/api/users", exempt))

    def test_no_leading_slash_in_exempt(self):
        """Test behavior when exempt path doesn't have leading slash."""
        exempt = {"health"}
        # Should not match since it becomes "health/"
        self.assertFalse(is_exempt_request_path("/health/check", exempt))

    def test_path_with_special_characters(self):
        """Test paths with special characters."""
        exempt = {"/api-v1"}
        self.assertTrue(is_exempt_request_path("/api-v1/users", exempt))
        self.assertFalse(is_exempt_request_path("/api-v2/users", exempt))

    def test_path_with_numbers(self):
        """Test paths with numbers."""
        exempt = {"/v1"}
        self.assertTrue(is_exempt_request_path("/v1/api", exempt))
        self.assertFalse(is_exempt_request_path("/v2/api", exempt))

    def test_case_sensitive_matching(self):
        """Test that path matching is case-sensitive."""
        exempt = {"/Health"}
        self.assertFalse(is_exempt_request_path("/health/check", exempt))
        self.assertTrue(is_exempt_request_path("/Health/check", exempt))

    def test_path_with_query_string(self):
        """Test paths that include query strings."""
        exempt = {"/search"}
        # Query strings should be part of the path being checked
        self.assertTrue(is_exempt_request_path("/search/results?q=test", exempt))

    def test_overlapping_prefixes(self):
        """Test with overlapping exempt prefixes."""
        exempt = {"/api", "/api/v1"}
        self.assertTrue(is_exempt_request_path("/api/users", exempt))
        self.assertTrue(is_exempt_request_path("/api/v1/users", exempt))

    def test_single_character_prefix(self):
        """Test single character prefix."""
        exempt = {"/a"}
        self.assertTrue(is_exempt_request_path("/a/b/c", exempt))
        self.assertFalse(is_exempt_request_path("/b/c", exempt))

    def test_path_with_dots(self):
        """Test paths with dots (e.g., file extensions)."""
        exempt = {"/static"}
        self.assertTrue(is_exempt_request_path("/static/images/logo.png", exempt))
        self.assertTrue(is_exempt_request_path("/static/css/style.css", exempt))

    def test_path_with_unicode(self):
        """Test paths with Unicode characters."""
        exempt = {"/api"}
        self.assertTrue(is_exempt_request_path("/api/用户", exempt))
        exempt_unicode = {"/用户"}
        self.assertTrue(is_exempt_request_path("/用户/profile", exempt_unicode))

    def test_multiple_trailing_slashes(self):
        """Test exempt paths with multiple trailing slashes."""
        exempt = {"/health//"}
        # After rstrip('/'), becomes "/health/"
        self.assertTrue(is_exempt_request_path("/health/check", exempt))

    def test_path_separator_edge_case(self):
        """Test that the path separator logic works correctly."""
        exempt = {"/app"}
        # These should NOT match
        self.assertFalse(is_exempt_request_path("/application", exempt))
        self.assertFalse(is_exempt_request_path("/app-admin", exempt))
        self.assertFalse(is_exempt_request_path("/apps", exempt))
        # This SHOULD match
        self.assertTrue(is_exempt_request_path("/app/status", exempt))

    def test_real_world_health_check_paths(self):
        """Test real-world health check endpoint patterns."""
        exempt = {"/health", "/healthz", "/_health"}
        self.assertTrue(is_exempt_request_path("/health/live", exempt))
        self.assertTrue(is_exempt_request_path("/health/ready", exempt))
        self.assertTrue(is_exempt_request_path("/healthz/status", exempt))
        self.assertTrue(is_exempt_request_path("/_health/check", exempt))
        self.assertFalse(is_exempt_request_path("/api/health", exempt))

    def test_real_world_monitoring_paths(self):
        """Test real-world monitoring endpoint patterns."""
        exempt = {"/metrics", "/status", "/actuator"}
        self.assertTrue(is_exempt_request_path("/metrics/prometheus", exempt))
        self.assertTrue(is_exempt_request_path("/status/app", exempt))
        self.assertTrue(is_exempt_request_path("/actuator/health", exempt))
        self.assertFalse(is_exempt_request_path("/api/metrics", exempt))
