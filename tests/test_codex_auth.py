# tests/test_codex_auth.py
import hashlib
import base64
import unittest
from urllib.parse import urlparse, parse_qs


class TestPKCE(unittest.TestCase):
    def test_code_verifier_length(self):
        """code_verifier should be 43-128 chars, URL-safe base64."""
        from codex_auth import generate_pkce_pair
        verifier, challenge = generate_pkce_pair()
        self.assertGreaterEqual(len(verifier), 43)
        self.assertLessEqual(len(verifier), 128)

    def test_code_verifier_is_url_safe(self):
        """code_verifier must only contain [A-Za-z0-9._~-]."""
        import re
        from codex_auth import generate_pkce_pair
        verifier, _ = generate_pkce_pair()
        self.assertRegex(verifier, r'^[A-Za-z0-9._~-]+$')

    def test_code_challenge_matches_verifier(self):
        """code_challenge = BASE64URL(SHA256(code_verifier)), no padding."""
        from codex_auth import generate_pkce_pair
        verifier, challenge = generate_pkce_pair()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('ascii')).digest()
        ).rstrip(b'=').decode('ascii')
        self.assertEqual(challenge, expected)

    def test_pkce_pairs_are_unique(self):
        """Each call should produce a different verifier."""
        from codex_auth import generate_pkce_pair
        v1, _ = generate_pkce_pair()
        v2, _ = generate_pkce_pair()
        self.assertNotEqual(v1, v2)


class TestAuthURL(unittest.TestCase):
    def test_auth_url_has_correct_base(self):
        from codex_auth import build_auth_url
        url, state = build_auth_url('test_challenge')
        parsed = urlparse(url)
        self.assertEqual(parsed.scheme, 'https')
        self.assertEqual(parsed.netloc, 'auth.openai.com')
        self.assertEqual(parsed.path, '/oauth/authorize')

    def test_auth_url_has_required_params(self):
        from codex_auth import build_auth_url
        url, state = build_auth_url('test_challenge')
        params = parse_qs(urlparse(url).query)
        self.assertEqual(params['client_id'], ['REDACTED_CODEX_CLIENT_ID'])
        self.assertEqual(params['redirect_uri'], ['http://localhost:1455/auth/callback'])
        self.assertEqual(params['response_type'], ['code'])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertEqual(params['code_challenge'], ['test_challenge'])
        self.assertIn('openid', params['scope'][0])
        self.assertIn('offline_access', params['scope'][0])

    def test_auth_url_state_is_returned(self):
        from codex_auth import build_auth_url
        url, state = build_auth_url('test_challenge')
        params = parse_qs(urlparse(url).query)
        self.assertEqual(params['state'], [state])
        self.assertGreater(len(state), 16)

    def test_auth_url_state_is_unique(self):
        from codex_auth import build_auth_url
        _, s1 = build_auth_url('c1')
        _, s2 = build_auth_url('c2')
        self.assertNotEqual(s1, s2)


class TestCallbackParser(unittest.TestCase):
    def test_extracts_code_and_state(self):
        from codex_auth import parse_callback_url
        url = 'http://localhost:1455/auth/callback?code=abc123&state=xyz789'
        code, state = parse_callback_url(url)
        self.assertEqual(code, 'abc123')
        self.assertEqual(state, 'xyz789')

    def test_extracts_code_with_scope(self):
        """Real callback URLs may include scope parameter."""
        from codex_auth import parse_callback_url
        url = 'http://localhost:1455/auth/callback?code=abc&scope=openid+profile&state=xyz'
        code, state = parse_callback_url(url)
        self.assertEqual(code, 'abc')
        self.assertEqual(state, 'xyz')

    def test_raises_on_missing_code(self):
        from codex_auth import parse_callback_url
        url = 'http://localhost:1455/auth/callback?state=xyz'
        with self.assertRaises(ValueError) as ctx:
            parse_callback_url(url)
        self.assertIn('code', str(ctx.exception).lower())

    def test_raises_on_error_response(self):
        """OAuth errors come as error= in the callback URL."""
        from codex_auth import parse_callback_url
        url = 'http://localhost:1455/auth/callback?error=access_denied&error_description=User+denied'
        with self.assertRaises(ValueError) as ctx:
            parse_callback_url(url)
        self.assertIn('access_denied', str(ctx.exception))

    def test_handles_url_without_scheme(self):
        """User might paste just the path+query."""
        from codex_auth import parse_callback_url
        url = 'localhost:1455/auth/callback?code=abc123&state=xyz789'
        code, state = parse_callback_url(url)
        self.assertEqual(code, 'abc123')


if __name__ == '__main__':
    unittest.main()
