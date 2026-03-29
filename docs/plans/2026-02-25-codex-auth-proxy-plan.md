# CodexAuthProxy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a zero-dependency Python CLI tool that performs the full OAuth 2.0 PKCE flow for OpenAI Codex CLI, enabling authentication on headless VPS environments.

**Architecture:** Single-file Python script with five internal modules: PKCE generator, auth URL builder, callback URL parser, token exchanger, and credential writer. User pastes the OAuth callback URL from their browser and the tool exchanges it for tokens, saving to `~/.codex/auth.json`.

**Tech Stack:** Python 3.6+ stdlib only (`secrets`, `hashlib`, `base64`, `urllib`, `json`, `os`, `pathlib`, `datetime`)

---

### Task 1: PKCE Generator

**Files:**
- Create: `codex_auth.py`
- Create: `tests/test_codex_auth.py`

**Step 1: Write the failing test**

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestPKCE -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'codex_auth'` or `ImportError`

**Step 3: Write minimal implementation**

```python
# codex_auth.py
"""CodexAuthProxy - OAuth PKCE authentication for Codex CLI on headless environments."""

import base64
import hashlib
import secrets


def generate_pkce_pair():
    """Generate a PKCE code_verifier and code_challenge (S256).

    Returns:
        tuple: (code_verifier, code_challenge) both as strings.
    """
    # Generate 96 random bytes -> base64url encode -> ~128 chars
    random_bytes = secrets.token_bytes(96)
    code_verifier = base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('ascii')
    # SHA-256 hash of the verifier, base64url-encoded without padding
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge
```

**Step 4: Run test to verify it passes**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestPKCE -v`
Expected: 4 tests PASS

**Step 5: Commit**

```bash
git add codex_auth.py tests/test_codex_auth.py
git commit -m "feat: add PKCE code_verifier/code_challenge generator"
```

---

### Task 2: Auth URL Builder

**Files:**
- Modify: `codex_auth.py`
- Modify: `tests/test_codex_auth.py`

**Context:** OAuth parameters discovered from Codex CLI source:
- Client ID: `<CODEX_CLIENT_ID>`
- Auth endpoint: `https://auth.openai.com/oauth/authorize`
- Token endpoint: `https://auth.openai.com/oauth/token`
- Redirect URI: `http://localhost:1455/auth/callback`
- Scope: `openid profile email offline_access`

**Step 1: Write the failing test**

Append to `tests/test_codex_auth.py`:

```python
from urllib.parse import urlparse, parse_qs


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
        self.assertEqual(params['client_id'], ['<CODEX_CLIENT_ID>'])
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
```

**Step 2: Run test to verify it fails**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestAuthURL -v`
Expected: FAIL with `ImportError: cannot import name 'build_auth_url'`

**Step 3: Write minimal implementation**

Add to `codex_auth.py`:

```python
from urllib.parse import urlencode

CLIENT_ID = '<CODEX_CLIENT_ID>'
AUTH_ENDPOINT = 'https://auth.openai.com/oauth/authorize'
TOKEN_ENDPOINT = 'https://auth.openai.com/oauth/token'
REDIRECT_URI = 'http://localhost:1455/auth/callback'
SCOPES = 'openid profile email offline_access'


def build_auth_url(code_challenge):
    """Build the OpenAI OAuth authorization URL.

    Args:
        code_challenge: The PKCE code challenge string.

    Returns:
        tuple: (authorization_url, state) where state is used for CSRF validation.
    """
    state = secrets.token_urlsafe(32)
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPES,
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
        'state': state,
    }
    url = f'{AUTH_ENDPOINT}?{urlencode(params)}'
    return url, state
```

**Step 4: Run test to verify it passes**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestAuthURL -v`
Expected: 4 tests PASS

**Step 5: Commit**

```bash
git add codex_auth.py tests/test_codex_auth.py
git commit -m "feat: add OAuth authorization URL builder"
```

---

### Task 3: Callback URL Parser

**Files:**
- Modify: `codex_auth.py`
- Modify: `tests/test_codex_auth.py`

**Step 1: Write the failing test**

Append to `tests/test_codex_auth.py`:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestCallbackParser -v`
Expected: FAIL with `ImportError: cannot import name 'parse_callback_url'`

**Step 3: Write minimal implementation**

Add to `codex_auth.py`:

```python
from urllib.parse import urlparse, parse_qs


def parse_callback_url(url):
    """Extract the authorization code and state from an OAuth callback URL.

    Args:
        url: The full callback URL from the browser address bar.

    Returns:
        tuple: (code, state) extracted from URL query parameters.

    Raises:
        ValueError: If the URL contains an error or is missing the code parameter.
    """
    # Handle URLs that may not have a scheme
    if not url.startswith('http'):
        url = 'http://' + url

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Check for OAuth error response
    if 'error' in params:
        error = params['error'][0]
        desc = params.get('error_description', [''])[0]
        raise ValueError(f'OAuth error: {error} - {desc}')

    if 'code' not in params:
        raise ValueError('Missing "code" parameter in callback URL. '
                         'Make sure you copied the full URL from the browser address bar.')

    code = params['code'][0]
    state = params.get('state', [None])[0]
    return code, state
```

**Step 4: Run test to verify it passes**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestCallbackParser -v`
Expected: 5 tests PASS

**Step 5: Commit**

```bash
git add codex_auth.py tests/test_codex_auth.py
git commit -m "feat: add callback URL parser with error handling"
```

---

### Task 4: Token Exchanger

**Files:**
- Modify: `codex_auth.py`
- Modify: `tests/test_codex_auth.py`

**Context:** This makes a real HTTP POST to OpenAI's token endpoint. Unit tests will mock `urllib.request.urlopen`.

**Step 1: Write the failing test**

Append to `tests/test_codex_auth.py`:

```python
from unittest.mock import patch, MagicMock
import json


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
        self.assertEqual(body['client_id'], ['<CODEX_CLIENT_ID>'])
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
```

**Step 2: Run test to verify it fails**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestTokenExchange -v`
Expected: FAIL with `ImportError: cannot import name 'exchange_code_for_tokens'`

**Step 3: Write minimal implementation**

Add to `codex_auth.py`:

```python
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import json


def exchange_code_for_tokens(code, code_verifier):
    """Exchange an authorization code for access/refresh tokens.

    Args:
        code: The authorization code from the OAuth callback.
        code_verifier: The original PKCE code_verifier.

    Returns:
        dict: Token response containing access_token, refresh_token, id_token, etc.

    Raises:
        ValueError: If the token exchange fails.
    """
    data = urlencode({
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier,
    }).encode('ascii')

    request = Request(TOKEN_ENDPOINT, data=data, method='POST')
    request.add_header('Content-Type', 'application/x-www-form-urlencoded')

    try:
        with urlopen(request) as response:
            return json.loads(response.read())
    except HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
            raise ValueError(
                f"Token exchange failed: {err.get('error', 'unknown')} - "
                f"{err.get('error_description', body)}"
            ) from e
        except json.JSONDecodeError:
            raise ValueError(f"Token exchange failed (HTTP {e.code}): {body}") from e
```

**Step 4: Run test to verify it passes**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestTokenExchange -v`
Expected: 3 tests PASS

**Step 5: Commit**

```bash
git add codex_auth.py tests/test_codex_auth.py
git commit -m "feat: add token exchange with OpenAI token endpoint"
```

---

### Task 5: Credential Writer

**Files:**
- Modify: `codex_auth.py`
- Modify: `tests/test_codex_auth.py`

**Context:** auth.json format expected by Codex CLI:
```json
{
  "auth_mode": "chatgpt",
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "id_token": "...",
    "expires_at": "2026-02-25T13:00:00Z"
  },
  "last_refresh": "2026-02-25T12:00:00Z"
}
```

**Step 1: Write the failing test**

Append to `tests/test_codex_auth.py`:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestCredentialWriter -v`
Expected: FAIL with `ImportError: cannot import name 'save_credentials'`

**Step 3: Write minimal implementation**

Add to `codex_auth.py`:

```python
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta


def save_credentials(token_response, codex_home=None):
    """Save OAuth tokens to ~/.codex/auth.json in the format Codex CLI expects.

    Args:
        token_response: Dict from the token endpoint (access_token, refresh_token, etc.)
        codex_home: Override for ~/.codex directory (used in tests).
    """
    if codex_home is None:
        codex_home = os.path.join(Path.home(), '.codex')

    os.makedirs(codex_home, exist_ok=True)
    auth_path = os.path.join(codex_home, 'auth.json')

    # Back up existing auth.json
    if os.path.exists(auth_path):
        bak_path = auth_path + '.bak'
        os.replace(auth_path, bak_path)

    now = datetime.now(timezone.utc)
    expires_in = token_response.get('expires_in', 3600)
    expires_at = now + timedelta(seconds=expires_in)

    credentials = {
        'auth_mode': 'chatgpt',
        'tokens': {
            'access_token': token_response['access_token'],
            'refresh_token': token_response['refresh_token'],
            'id_token': token_response.get('id_token', ''),
            'expires_at': expires_at.strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
        'last_refresh': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
    }

    # Write with restricted permissions
    fd = os.open(auth_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(credentials, f, indent=2)
            f.write('\n')
    except Exception:
        os.close(fd)
        raise
```

**Step 4: Run test to verify it passes**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestCredentialWriter -v`
Expected: 4 tests PASS

**Step 5: Commit**

```bash
git add codex_auth.py tests/test_codex_auth.py
git commit -m "feat: add credential writer for ~/.codex/auth.json"
```

---

### Task 6: Main CLI Flow

**Files:**
- Modify: `codex_auth.py`
- Modify: `tests/test_codex_auth.py`

**Step 1: Write the failing test**

Append to `tests/test_codex_auth.py`:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestMainFlow -v`
Expected: FAIL with `ImportError: cannot import name 'main'`

**Step 3: Write minimal implementation**

Add to `codex_auth.py`:

```python
import sys


def main():
    """Run the CodexAuthProxy OAuth flow."""
    print('\n=== CodexAuthProxy ===')
    print('Headless OAuth authentication for OpenAI Codex CLI\n')

    # Step 1: Generate PKCE pair
    print('Generating PKCE challenge...')
    code_verifier, code_challenge = generate_pkce_pair()

    # Step 2: Build and display auth URL
    auth_url, expected_state = build_auth_url(code_challenge)
    print('\nStep 1: Open this URL in any browser and sign in with ChatGPT:')
    print(f'\n  {auth_url}\n')
    print('Step 2: After signing in, the browser will try to redirect to')
    print('        localhost:1455 and FAIL. That\'s expected!')
    print('\nStep 3: Copy the FULL URL from the browser\'s address bar')
    print('        (it starts with http://localhost:1455/auth/callback?...)')

    # Step 3: Get callback URL from user
    callback_url = input('\nPaste the callback URL here: ').strip()

    if not callback_url:
        print('Error: No URL provided.')
        sys.exit(1)

    # Step 4: Parse callback URL
    try:
        code, state = parse_callback_url(callback_url)
    except ValueError as e:
        print(f'\nError: {e}')
        sys.exit(1)

    # Step 5: Validate state (CSRF protection)
    if state != expected_state:
        print('\nError: State mismatch - possible CSRF attack or stale URL.')
        print('Please start over and use a fresh authorization URL.')
        sys.exit(1)

    # Step 6: Exchange code for tokens
    print('\nExchanging authorization code for tokens...')
    try:
        tokens = exchange_code_for_tokens(code, code_verifier)
    except ValueError as e:
        print(f'\nError: {e}')
        sys.exit(1)

    # Step 7: Save credentials
    save_credentials(tokens)
    print('\nSuccess! Credentials saved to ~/.codex/auth.json')
    print('You can now use `codex` normally.')


if __name__ == '__main__':
    main()
```

**Step 4: Run test to verify it passes**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py::TestMainFlow -v`
Expected: 2 tests PASS

**Step 5: Run all tests**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py -v`
Expected: All 18 tests PASS

**Step 6: Commit**

```bash
git add codex_auth.py tests/test_codex_auth.py
git commit -m "feat: add main CLI flow tying all components together"
```

---

### Task 7: Final Integration & Cleanup

**Files:**
- Modify: `codex_auth.py` (ensure all imports are at top, clean organization)

**Step 1: Verify the complete script runs**

Run: `cd /home/app/CodexAuthProxy && python3 codex_auth.py --help 2>&1 || python3 -c "import codex_auth; print('Import OK')"`
Expected: Either shows usage or prints "Import OK" (no import errors)

**Step 2: Run full test suite**

Run: `cd /home/app/CodexAuthProxy && python3 -m pytest tests/test_codex_auth.py -v --tb=short`
Expected: All 18 tests PASS

**Step 3: Commit final version**

```bash
git add codex_auth.py tests/test_codex_auth.py
git commit -m "chore: final cleanup and integration verification"
```
