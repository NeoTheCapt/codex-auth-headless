"""CodexAuthProxy - OAuth PKCE authentication for Codex CLI on headless environments."""

import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import json
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta

CLIENT_ID = 'REDACTED_CODEX_CLIENT_ID'
AUTH_ENDPOINT = 'https://auth.openai.com/oauth/authorize'
TOKEN_ENDPOINT = 'https://auth.openai.com/oauth/token'
REDIRECT_URI = 'http://localhost:1455/auth/callback'
SCOPES = 'openid profile email offline_access'


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
