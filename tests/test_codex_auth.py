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


from unittest.mock import patch, MagicMock
import json


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


class TestTokenExchange(unittest.TestCase):
    @patch('codex_auth.urlopen')
    def test_sends_correct_post_body(self, mock_urlopen):
        """Token exchange should POST correct params to token endpoint."""
        from codex_auth import exchange_code_for_tokens, TOKEN_ENDPOINT

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'access_token': 'at_123',
            'refresh_token': 'rt_456',
            'id_token': 'id_789',
            'expires_in': 3600,
            'token_type': 'Bearer',
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = exchange_code_for_tokens('auth_code_abc', 'my_verifier')

        # Verify the request
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.full_url, TOKEN_ENDPOINT)
        self.assertEqual(request.get_method(), 'POST')

        body = parse_qs(request.data.decode())
        self.assertEqual(body['grant_type'], ['authorization_code'])
        self.assertEqual(body['code'], ['auth_code_abc'])
        self.assertEqual(body['code_verifier'], ['my_verifier'])
        self.assertEqual(body['client_id'], ['REDACTED_CODEX_CLIENT_ID'])
        self.assertEqual(body['redirect_uri'], ['http://localhost:1455/auth/callback'])

    @patch('codex_auth.urlopen')
    def test_returns_parsed_tokens(self, mock_urlopen):
        """Should return the parsed JSON token response."""
        from codex_auth import exchange_code_for_tokens

        token_data = {
            'access_token': 'at_123',
            'refresh_token': 'rt_456',
            'id_token': 'id_789',
            'expires_in': 3600,
            'token_type': 'Bearer',
        }
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(token_data).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = exchange_code_for_tokens('code', 'verifier')
        self.assertEqual(result['access_token'], 'at_123')
        self.assertEqual(result['refresh_token'], 'rt_456')
        self.assertEqual(result['id_token'], 'id_789')
        self.assertEqual(result['expires_in'], 3600)

    @patch('codex_auth.urlopen')
    def test_raises_on_http_error(self, mock_urlopen):
        """Should raise ValueError with error details on HTTP failure."""
        from codex_auth import exchange_code_for_tokens
        from urllib.error import HTTPError
        import io

        error_body = json.dumps({'error': 'invalid_grant', 'error_description': 'Code expired'})
        mock_urlopen.side_effect = HTTPError(
            url='https://auth.openai.com/oauth/token',
            code=400,
            msg='Bad Request',
            hdrs={},
            fp=io.BytesIO(error_body.encode())
        )

        with self.assertRaises(ValueError) as ctx:
            exchange_code_for_tokens('bad_code', 'verifier')
        self.assertIn('invalid_grant', str(ctx.exception))


import tempfile
import os


class TestCredentialWriter(unittest.TestCase):
    def test_creates_auth_json(self):
        from codex_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            token_response = {
                'access_token': 'at_test',
                'refresh_token': 'rt_test',
                'id_token': 'id_test',
                'expires_in': 3600,
                'token_type': 'Bearer',
            }
            save_credentials(token_response, codex_home=tmpdir)

            auth_path = os.path.join(tmpdir, 'auth.json')
            self.assertTrue(os.path.exists(auth_path))

            with open(auth_path) as f:
                saved = json.load(f)

            self.assertEqual(saved['auth_mode'], 'chatgpt')
            self.assertEqual(saved['tokens']['access_token'], 'at_test')
            self.assertEqual(saved['tokens']['refresh_token'], 'rt_test')
            self.assertEqual(saved['tokens']['id_token'], 'id_test')
            self.assertIn('expires_at', saved['tokens'])
            self.assertIn('last_refresh', saved)

    def test_creates_codex_dir_if_missing(self):
        from codex_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            codex_dir = os.path.join(tmpdir, 'nonexistent', '.codex')
            save_credentials({'access_token': 'a', 'refresh_token': 'r',
                              'id_token': 'i', 'expires_in': 3600},
                             codex_home=codex_dir)
            self.assertTrue(os.path.exists(os.path.join(codex_dir, 'auth.json')))

    def test_backs_up_existing_auth_json(self):
        from codex_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_path = os.path.join(tmpdir, 'auth.json')
            with open(auth_path, 'w') as f:
                f.write('{"old": "data"}')

            save_credentials({'access_token': 'new', 'refresh_token': 'r',
                              'id_token': 'i', 'expires_in': 3600},
                             codex_home=tmpdir)

            bak_path = os.path.join(tmpdir, 'auth.json.bak')
            self.assertTrue(os.path.exists(bak_path))
            with open(bak_path) as f:
                self.assertIn('old', f.read())

    def test_file_permissions(self):
        """auth.json should be readable/writable only by owner (0o600)."""
        from codex_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            save_credentials({'access_token': 'a', 'refresh_token': 'r',
                              'id_token': 'i', 'expires_in': 3600},
                             codex_home=tmpdir)
            auth_path = os.path.join(tmpdir, 'auth.json')
            mode = os.stat(auth_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)


class TestMainFlow(unittest.TestCase):
    @patch('codex_auth.exchange_code_for_tokens')
    @patch('codex_auth.save_credentials')
    @patch('builtins.input')
    def test_main_flow_happy_path(self, mock_input, mock_save, mock_exchange):
        """main() should orchestrate: PKCE -> URL -> paste -> exchange -> save."""
        from codex_auth import main

        mock_input.return_value = 'http://localhost:1455/auth/callback?code=test_code&state={state}'
        mock_exchange.return_value = {
            'access_token': 'at', 'refresh_token': 'rt',
            'id_token': 'id', 'expires_in': 3600,
        }

        # We need to capture the state to inject it into the mock input
        # This test verifies the flow calls the right functions in order
        with patch('codex_auth.generate_pkce_pair', return_value=('verifier', 'challenge')):
            with patch('codex_auth.build_auth_url', return_value=('https://auth.example.com', 'test_state')):
                mock_input.return_value = 'http://localhost:1455/auth/callback?code=test_code&state=test_state'
                main()

        mock_exchange.assert_called_once_with('test_code', 'verifier')
        mock_save.assert_called_once()

    @patch('codex_auth.exchange_code_for_tokens')
    @patch('codex_auth.save_credentials')
    @patch('builtins.input')
    def test_main_flow_state_mismatch_aborts(self, mock_input, mock_save, mock_exchange):
        """main() should abort if state doesn't match (CSRF protection)."""
        from codex_auth import main

        with patch('codex_auth.generate_pkce_pair', return_value=('verifier', 'challenge')):
            with patch('codex_auth.build_auth_url', return_value=('https://auth.example.com', 'expected_state')):
                mock_input.return_value = 'http://localhost:1455/auth/callback?code=c&state=wrong_state'
                with self.assertRaises(SystemExit):
                    main()

        mock_exchange.assert_not_called()
        mock_save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
