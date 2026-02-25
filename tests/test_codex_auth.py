# tests/test_codex_auth.py
import hashlib
import base64
import unittest


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


if __name__ == '__main__':
    unittest.main()
