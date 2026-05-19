"""ClaudeAuthProxy - OAuth PKCE authentication for Claude Code on headless environments."""

import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import json
import os
import sys
from pathlib import Path

AUTH_ENDPOINT = 'https://claude.com/cai/oauth/authorize'
TOKEN_ENDPOINT = 'https://platform.claude.com/v1/oauth/token'
REDIRECT_URI = 'https://platform.claude.com/oauth/code/callback'
SCOPES = 'org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload'


def _load_env_file():
    """Load variables from .env file if it exists."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key not in os.environ:
                os.environ[key] = value


_load_env_file()


def get_client_id():
    """Get the Claude OAuth client ID from environment."""
    client_id = os.environ.get('CLAUDE_CLIENT_ID')
    if not client_id:
        print('Error: CLAUDE_CLIENT_ID not set.')
        print('Set it via environment variable or .env file.')
        sys.exit(1)
    return client_id


def generate_pkce_pair():
    """Generate a PKCE code_verifier and code_challenge (S256).

    Returns:
        tuple: (code_verifier, code_challenge) both as strings.
    """
    random_bytes = secrets.token_bytes(96)
    code_verifier = base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('ascii')
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge


def build_auth_url(code_challenge):
    """Build the Claude OAuth authorization URL.

    Args:
        code_challenge: The PKCE code challenge string.

    Returns:
        tuple: (authorization_url, state) where state is used for CSRF validation.
    """
    state = secrets.token_urlsafe(32)
    params = {
        'code': 'true',
        'client_id': get_client_id(),
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPES,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'state': state,
    }
    url = f'{AUTH_ENDPOINT}?{urlencode(params)}'
    return url, state


def parse_callback_input(user_input):
    """Extract the authorization code and state from user input.

    Accepts either a bare authorization code or a full callback URL.

    Args:
        user_input: The raw string pasted by the user.

    Returns:
        tuple: (authorization_code, state, redirect_uri). state and redirect_uri
        may be None when the user pastes a bare code.

    Raises:
        ValueError: If the input contains an error or no code can be extracted.
    """
    user_input = user_input.strip()

    if not user_input:
        raise ValueError('No input provided.')

    # Check if it looks like a URL
    if '://' in user_input or user_input.startswith('http'):
        if not user_input.startswith('http'):
            user_input = 'http://' + user_input

        parsed = urlparse(user_input)
        params = parse_qs(parsed.query)

        if 'error' in params:
            error = params['error'][0]
            desc = params.get('error_description', [''])[0]
            raise ValueError(f'OAuth error: {error} - {desc}')

        if 'code' not in params:
            raise ValueError('Missing "code" parameter in callback URL. '
                             'Make sure you copied the full URL.')

        redirect_uri = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
        state = params.get('state', [None])[0]
        return params['code'][0], state, redirect_uri

    # The callback page may show code#state.
    if '#' in user_input:
        code, state = user_input.split('#', 1)
        return code, state or None, None

    return user_input, None, None


def _format_token_error(body):
    """Return a readable OAuth error message from a token endpoint body."""
    try:
        err = json.loads(body)
    except json.JSONDecodeError:
        return body

    error = err.get('error', err)
    if isinstance(error, dict):
        error_type = error.get('type') or err.get('type') or 'unknown'
        message = error.get('message') or error.get('error_description') or body
    else:
        error_type = error or err.get('type') or 'unknown'
        message = err.get('error_description') or err.get('message') or body

    request_id = err.get('request_id')
    if request_id:
        return f'{error_type}: {message} (request_id: {request_id})'
    return f'{error_type}: {message}'


def exchange_code_for_tokens(code, code_verifier, state, redirect_uri=REDIRECT_URI):
    """Exchange an authorization code for access/refresh tokens.

    Args:
        code: The authorization code from the OAuth callback.
        code_verifier: The original PKCE code_verifier.
        state: The OAuth state value from the authorization request.
        redirect_uri: The redirect URI used by the authorization request.

    Returns:
        dict: Token response containing access_token, refresh_token, etc.

    Raises:
        ValueError: If the token exchange fails.
    """
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': get_client_id(),
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
        'state': state,
    }
    data = json.dumps(payload).encode('utf-8')

    request = Request(TOKEN_ENDPOINT, data=data, method='POST')
    request.add_header('Content-Type', 'application/json')
    request.add_header('User-Agent', 'claude-code/1.0')

    try:
        with urlopen(request) as response:
            return json.loads(response.read())
    except HTTPError as e:
        body = e.read().decode()
        raise ValueError(
            f'Token exchange failed (HTTP {e.code}): {_format_token_error(body)}'
        ) from e


def _scope_list(scope_value):
    """Normalize an OAuth scope response into Claude Code's credential shape."""
    if isinstance(scope_value, str):
        return [scope for scope in scope_value.split() if scope]
    if isinstance(scope_value, list):
        return scope_value
    return SCOPES.split()


def save_credentials(token_response, claude_home=None):
    """Save OAuth tokens to ~/.claude/.credentials.json in the format Claude Code expects.

    Args:
        token_response: Dict from the token endpoint (access_token, refresh_token, etc.)
        claude_home: Override for ~/.claude directory (used in tests).
    """
    if claude_home is None:
        claude_home = os.path.join(Path.home(), '.claude')

    os.makedirs(claude_home, exist_ok=True)
    cred_path = os.path.join(claude_home, '.credentials.json')

    # Back up existing credentials
    if os.path.exists(cred_path):
        bak_path = cred_path + '.bak'
        os.replace(cred_path, bak_path)

    expires_in = token_response.get('expires_in', 3600)
    # Claude Code uses Unix timestamp in milliseconds
    import time
    expires_at = int((time.time() + expires_in) * 1000)

    credentials = {
        'claudeAiOauth': {
            'accessToken': token_response['access_token'],
            'refreshToken': token_response['refresh_token'],
            'expiresAt': expires_at,
            'scopes': _scope_list(token_response.get('scope')),
            'clientId': get_client_id(),
        },
    }

    # Write with restricted permissions
    fd = os.open(cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(credentials, f, indent=2)
            f.write('\n')
    except Exception:
        os.close(fd)
        raise


def main():
    """Run the ClaudeAuthProxy OAuth flow."""
    print('\n=== ClaudeAuthProxy ===')
    print('Headless OAuth authentication for Claude Code\n')

    # Step 1: Generate PKCE pair
    print('Generating PKCE challenge...')
    code_verifier, code_challenge = generate_pkce_pair()

    # Step 2: Build and display auth URL
    auth_url, expected_state = build_auth_url(code_challenge)
    print('\nStep 1: Open this URL in any browser and sign in with your Claude account:')
    print(f'\n  {auth_url}\n')
    print('Step 2: After signing in, the browser will redirect to Anthropic\'s console')
    print('        which will display an authorization code.')
    print('\nStep 3: Copy the authorization code shown on the page.')
    print('        (You can also paste the full callback URL if you prefer)')

    # Step 3: Get input from user
    user_input = input('\nPaste the authorization code (or callback URL) here: ').strip()

    if not user_input:
        print('Error: No input provided.')
        sys.exit(1)

    # Step 4: Parse input
    try:
        code, returned_state, callback_redirect_uri = parse_callback_input(user_input)
    except ValueError as e:
        print(f'\nError: {e}')
        sys.exit(1)

    if returned_state and returned_state != expected_state:
        print('\nError: OAuth state mismatch.')
        print('The pasted code/URL appears to come from a different login attempt.')
        print('Open the URL printed by this script again and paste the new code from that flow.')
        sys.exit(1)

    state = returned_state or expected_state
    redirect_uri = callback_redirect_uri or REDIRECT_URI

    # Step 5: Exchange code for tokens
    print('\nExchanging authorization code for tokens...')
    try:
        tokens = exchange_code_for_tokens(code, code_verifier, state, redirect_uri)
    except ValueError as e:
        print(f'\nError: {e}')
        sys.exit(1)

    # Step 6: Save credentials
    save_credentials(tokens)
    print('\nSuccess! Credentials saved to ~/.claude/.credentials.json')
    print('You can now use Claude Code normally.')


if __name__ == '__main__':
    main()
