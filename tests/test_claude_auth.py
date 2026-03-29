# tests/test_claude_auth.py
import hashlib
import base64
import unittest
from urllib.parse import urlparse, parse_qs


class TestPKCE(unittest.TestCase):
    def test_code_verifier_length(self):
        """code_verifier should be 43-128 chars, URL-safe base64."""
        from claude_auth import generate_pkce_pair
        verifier, challenge = generate_pkce_pair()
        self.assertGreaterEqual(len(verifier), 43)
        self.assertLessEqual(len(verifier), 128)

    def test_code_verifier_is_url_safe(self):
        """code_verifier must only contain [A-Za-z0-9._~-]."""
        import re
        from claude_auth import generate_pkce_pair
        verifier, _ = generate_pkce_pair()
        self.assertRegex(verifier, r'^[A-Za-z0-9._~-]+$')

    def test_code_challenge_matches_verifier(self):
        """code_challenge = BASE64URL(SHA256(code_verifier)), no padding."""
        from claude_auth import generate_pkce_pair
        verifier, challenge = generate_pkce_pair()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('ascii')).digest()
        ).rstrip(b'=').decode('ascii')
        self.assertEqual(challenge, expected)

    def test_pkce_pairs_are_unique(self):
        """Each call should produce a different verifier."""
        from claude_auth import generate_pkce_pair
        v1, _ = generate_pkce_pair()
        v2, _ = generate_pkce_pair()
        self.assertNotEqual(v1, v2)


class TestAuthURL(unittest.TestCase):
    def test_auth_url_has_correct_base(self):
        from claude_auth import build_auth_url
        url, state = build_auth_url('test_challenge')
        parsed = urlparse(url)
        self.assertEqual(parsed.scheme, 'https')
        self.assertEqual(parsed.netloc, 'claude.com')
        self.assertEqual(parsed.path, '/cai/oauth/authorize')

    def test_auth_url_has_required_params(self):
        from claude_auth import build_auth_url
        url, state = build_auth_url('test_challenge')
        params = parse_qs(urlparse(url).query)
        self.assertEqual(params['code'], ['true'])
        self.assertEqual(params['client_id'], ['REDACTED_CLAUDE_CLIENT_ID'])
        self.assertEqual(params['redirect_uri'], ['https://platform.claude.com/oauth/code/callback'])
        self.assertEqual(params['response_type'], ['code'])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertEqual(params['code_challenge'], ['test_challenge'])
        self.assertIn('org:create_api_key', params['scope'][0])
        self.assertIn('user:profile', params['scope'][0])
        self.assertIn('user:inference', params['scope'][0])
        self.assertIn('user:sessions:claude_code', params['scope'][0])
        self.assertIn('user:mcp_servers', params['scope'][0])
        self.assertIn('user:file_upload', params['scope'][0])

    def test_auth_url_state_is_returned(self):
        from claude_auth import build_auth_url
        url, state = build_auth_url('test_challenge')
        params = parse_qs(urlparse(url).query)
        self.assertEqual(params['state'], [state])
        self.assertGreater(len(state), 16)

    def test_auth_url_state_is_unique(self):
        from claude_auth import build_auth_url
        _, s1 = build_auth_url('c1')
        _, s2 = build_auth_url('c2')
        self.assertNotEqual(s1, s2)


from unittest.mock import patch, MagicMock
import json


class TestCallbackInputParser(unittest.TestCase):
    def test_extracts_code_from_url(self):
        from claude_auth import parse_callback_input
        url = 'https://platform.claude.com/oauth/code/callback?code=abc123'
        code = parse_callback_input(url)
        self.assertEqual(code, 'abc123')

    def test_extracts_code_from_url_with_extra_params(self):
        from claude_auth import parse_callback_input
        url = 'https://platform.claude.com/oauth/code/callback?code=abc&state=xyz&scope=test'
        code = parse_callback_input(url)
        self.assertEqual(code, 'abc')

    def test_accepts_bare_code(self):
        """User might paste just the authorization code."""
        from claude_auth import parse_callback_input
        code = parse_callback_input('sk-ant-auth-abc123xyz')
        self.assertEqual(code, 'sk-ant-auth-abc123xyz')

    def test_accepts_bare_code_with_whitespace(self):
        from claude_auth import parse_callback_input
        code = parse_callback_input('  some_code_value  ')
        self.assertEqual(code, 'some_code_value')

    def test_raises_on_empty_input(self):
        from claude_auth import parse_callback_input
        with self.assertRaises(ValueError) as ctx:
            parse_callback_input('')
        self.assertIn('No input', str(ctx.exception))

    def test_raises_on_missing_code_in_url(self):
        from claude_auth import parse_callback_input
        url = 'https://platform.claude.com/oauth/code/callback?state=xyz'
        with self.assertRaises(ValueError) as ctx:
            parse_callback_input(url)
        self.assertIn('code', str(ctx.exception).lower())

    def test_raises_on_error_response(self):
        from claude_auth import parse_callback_input
        url = 'https://platform.claude.com/oauth/code/callback?error=access_denied&error_description=User+denied'
        with self.assertRaises(ValueError) as ctx:
            parse_callback_input(url)
        self.assertIn('access_denied', str(ctx.exception))


class TestTokenExchange(unittest.TestCase):
    @patch('claude_auth.urlopen')
    def test_sends_correct_post_body(self, mock_urlopen):
        from claude_auth import exchange_code_for_tokens, TOKEN_ENDPOINT

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'access_token': 'at_123',
            'refresh_token': 'rt_456',
            'expires_in': 3600,
            'token_type': 'Bearer',
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = exchange_code_for_tokens('auth_code_abc', 'my_verifier')

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        self.assertEqual(request.full_url, TOKEN_ENDPOINT)
        self.assertEqual(request.get_method(), 'POST')

        body = parse_qs(request.data.decode())
        self.assertEqual(body['grant_type'], ['authorization_code'])
        self.assertEqual(body['code'], ['auth_code_abc'])
        self.assertEqual(body['code_verifier'], ['my_verifier'])
        self.assertEqual(body['client_id'], ['REDACTED_CLAUDE_CLIENT_ID'])
        self.assertEqual(body['redirect_uri'], ['https://platform.claude.com/oauth/code/callback'])

    @patch('claude_auth.urlopen')
    def test_returns_parsed_tokens(self, mock_urlopen):
        from claude_auth import exchange_code_for_tokens

        token_data = {
            'access_token': 'at_123',
            'refresh_token': 'rt_456',
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
        self.assertEqual(result['expires_in'], 3600)

    @patch('claude_auth.urlopen')
    def test_raises_on_http_error(self, mock_urlopen):
        from claude_auth import exchange_code_for_tokens
        from urllib.error import HTTPError
        import io

        error_body = json.dumps({'error': 'invalid_grant', 'error_description': 'Code expired'})
        mock_urlopen.side_effect = HTTPError(
            url='https://platform.claude.com/v1/oauth/token',
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
    def test_creates_credentials_json(self):
        from claude_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            token_response = {
                'access_token': 'sk-ant-oat01-test',
                'refresh_token': 'rt_test',
                'expires_in': 3600,
                'token_type': 'Bearer',
            }
            save_credentials(token_response, claude_home=tmpdir)

            cred_path = os.path.join(tmpdir, '.credentials.json')
            self.assertTrue(os.path.exists(cred_path))

            with open(cred_path) as f:
                saved = json.load(f)

            self.assertIn('claudeAiOauth', saved)
            oauth = saved['claudeAiOauth']
            self.assertEqual(oauth['accessToken'], 'sk-ant-oat01-test')
            self.assertEqual(oauth['refreshToken'], 'rt_test')
            self.assertIsInstance(oauth['expiresAt'], int)
            # expiresAt should be in milliseconds (> 1 trillion)
            self.assertGreater(oauth['expiresAt'], 1_000_000_000_000)

    def test_creates_claude_dir_if_missing(self):
        from claude_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            claude_dir = os.path.join(tmpdir, 'nonexistent', '.claude')
            save_credentials({'access_token': 'a', 'refresh_token': 'r',
                              'expires_in': 3600},
                             claude_home=claude_dir)
            self.assertTrue(os.path.exists(os.path.join(claude_dir, '.credentials.json')))

    def test_backs_up_existing_credentials(self):
        from claude_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            cred_path = os.path.join(tmpdir, '.credentials.json')
            with open(cred_path, 'w') as f:
                f.write('{"old": "data"}')

            save_credentials({'access_token': 'new', 'refresh_token': 'r',
                              'expires_in': 3600},
                             claude_home=tmpdir)

            bak_path = os.path.join(tmpdir, '.credentials.json.bak')
            self.assertTrue(os.path.exists(bak_path))
            with open(bak_path) as f:
                self.assertIn('old', f.read())

    def test_file_permissions(self):
        """.credentials.json should be readable/writable only by owner (0o600)."""
        from claude_auth import save_credentials
        with tempfile.TemporaryDirectory() as tmpdir:
            save_credentials({'access_token': 'a', 'refresh_token': 'r',
                              'expires_in': 3600},
                             claude_home=tmpdir)
            cred_path = os.path.join(tmpdir, '.credentials.json')
            mode = os.stat(cred_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)


class TestMainFlow(unittest.TestCase):
    @patch('claude_auth.exchange_code_for_tokens')
    @patch('claude_auth.save_credentials')
    @patch('builtins.input')
    def test_main_flow_happy_path_with_bare_code(self, mock_input, mock_save, mock_exchange):
        """main() should work when user pastes a bare authorization code."""
        from claude_auth import main

        mock_exchange.return_value = {
            'access_token': 'at', 'refresh_token': 'rt',
            'expires_in': 3600,
        }

        with patch('claude_auth.generate_pkce_pair', return_value=('verifier', 'challenge')):
            with patch('claude_auth.build_auth_url', return_value=('https://claude.ai/oauth/authorize?...', 'test_state')):
                mock_input.return_value = 'my_auth_code_123'
                main()

        mock_exchange.assert_called_once_with('my_auth_code_123', 'verifier')
        mock_save.assert_called_once()

    @patch('claude_auth.exchange_code_for_tokens')
    @patch('claude_auth.save_credentials')
    @patch('builtins.input')
    def test_main_flow_happy_path_with_url(self, mock_input, mock_save, mock_exchange):
        """main() should work when user pastes the full callback URL."""
        from claude_auth import main

        mock_exchange.return_value = {
            'access_token': 'at', 'refresh_token': 'rt',
            'expires_in': 3600,
        }

        with patch('claude_auth.generate_pkce_pair', return_value=('verifier', 'challenge')):
            with patch('claude_auth.build_auth_url', return_value=('https://claude.ai/oauth/authorize?...', 'test_state')):
                mock_input.return_value = 'https://console.anthropic.com/oauth/code/callback?code=url_code_456'
                main()

        mock_exchange.assert_called_once_with('url_code_456', 'verifier')
        mock_save.assert_called_once()

    @patch('claude_auth.exchange_code_for_tokens')
    @patch('claude_auth.save_credentials')
    @patch('builtins.input')
    def test_main_flow_empty_input_aborts(self, mock_input, mock_save, mock_exchange):
        from claude_auth import main

        with patch('claude_auth.generate_pkce_pair', return_value=('verifier', 'challenge')):
            with patch('claude_auth.build_auth_url', return_value=('https://example.com', 'state')):
                mock_input.return_value = ''
                with self.assertRaises(SystemExit):
                    main()

        mock_exchange.assert_not_called()
        mock_save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
