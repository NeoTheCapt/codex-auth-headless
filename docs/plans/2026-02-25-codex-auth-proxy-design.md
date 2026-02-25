# CodexAuthProxy Design

## Problem

OpenAI Codex CLI on a headless VPS cannot complete OAuth authentication because:
1. The CLI opens an auth URL that requires a browser
2. After authenticating in a browser on another machine (e.g., laptop), the OAuth callback redirects to `http://localhost:1455/auth/callback`
3. The Codex CLI's callback listener is on the VPS, not the laptop, so the redirect fails
4. SSH port forwarding is not viable due to complex network conditions
5. Curling the callback URL to the VPS's localhost:1455 hangs

## Solution

A standalone Python CLI tool that implements the full OAuth 2.0 PKCE flow independently, bypassing the Codex CLI's built-in auth server entirely. The tool generates auth credentials and saves them to `~/.codex/auth.json` where Codex CLI expects them.

## Approach

**Single-file Python script** with zero external dependencies (stdlib only). Chosen over a Python package (unnecessary complexity) and clipboard integration (doesn't work on headless VPS).

## Architecture

Five components in one file (`codex_auth.py`):

### 1. PKCE Generator
- Creates cryptographically secure `code_verifier` (128 random bytes, base64url-encoded)
- Derives `code_challenge` (SHA-256 hash of verifier, base64url-encoded)

### 2. Auth URL Builder
Constructs the OpenAI authorization URL with:
- `client_id`: `REDACTED_CODEX_CLIENT_ID` (Codex CLI's registered OAuth client)
- `redirect_uri`: `http://localhost:1455/auth/callback`
- `response_type`: `code`
- `code_challenge_method`: `S256`
- `code_challenge`: generated value
- `scope`: `openid profile email offline_access`
- `state`: random string for CSRF protection

### 3. Callback URL Parser
- Extracts `code` and `state` query parameters from the user-pasted URL
- Validates `state` matches the generated value

### 4. Token Exchanger
POSTs to `https://auth.openai.com/oauth/token` with:
- `grant_type`: `authorization_code`
- `code`: from callback URL
- `code_verifier`: generated earlier
- `client_id`: same as above
- `redirect_uri`: same as above (must match)

### 5. Credential Writer
- Creates `~/.codex/` directory if needed
- Backs up existing `auth.json` if present
- Saves token response to `~/.codex/auth.json`

## User Flow

```
$ python3 codex_auth.py

=== Codex Auth Proxy ===
Generating PKCE challenge...

Step 1: Open this URL in any browser and sign in:
https://auth.openai.com/oauth/authorize?client_id=...&code_challenge=...

Step 2: After signing in, the browser will try to redirect to localhost:1455
         and FAIL. That's expected!

Step 3: Copy the FULL URL from the browser's address bar and paste it here:
> http://localhost:1455/auth/callback?code=abc123&state=yyyy

Exchanging authorization code for tokens...
Success! Credentials saved to ~/.codex/auth.json
```

## Error Handling

- Invalid/malformed pasted URL: clear error message, prompt to retry
- State mismatch: warn about potential CSRF, abort
- Token exchange failure: show OpenAI's error response
- Missing `~/.codex/` directory: create it automatically
- Existing `auth.json`: back up to `auth.json.bak` before overwriting

## auth.json Format

The tool saves the full token endpoint response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "v1.xxx...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJ..."
}
```

Codex CLI handles token refresh on its own after initial login.

## File Structure

```
CodexAuthProxy/
├── codex_auth.py          # Main script (single file, zero deps)
├── tests/
│   └── test_codex_auth.py # Unit tests
└── README.md              # Usage instructions
```

## Testing Strategy

- Unit test PKCE generation (verify challenge matches verifier)
- Unit test URL parser (extract code/state from various URL formats)
- Manual end-to-end test with actual Codex auth

## Key Technical Details

- OAuth endpoints: `https://auth.openai.com/oauth/authorize` and `https://auth.openai.com/oauth/token`
- Client ID: `REDACTED_CODEX_CLIENT_ID`
- Callback port: 1455 (hardcoded in OpenAI's OAuth app registration)
- PKCE method: S256
- Python 3.6+ compatible (uses only stdlib: `secrets`, `hashlib`, `base64`, `urllib`, `json`, `os`, `pathlib`)

## Sources

- [OpenAI Codex Auth Docs](https://developers.openai.com/codex/auth/)
- [codex-get-auth-conf](https://github.com/pedrobrantes/codex-get-auth-conf) — TypeScript reference implementation
- [GitHub Issue #2798](https://github.com/openai/codex/issues/2798) — headless OAuth support request
- [GitHub Issue #8112](https://github.com/openai/codex/issues/8112) — localhost:1455 callback issues
