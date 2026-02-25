"""CodexAuthProxy - OAuth PKCE authentication for Codex CLI on headless environments."""

import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlparse, parse_qs

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
