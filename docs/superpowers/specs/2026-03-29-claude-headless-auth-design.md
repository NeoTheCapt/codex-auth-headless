# Claude Headless Auth Design

## Summary

Add `claude_auth.py` — a standalone headless OAuth PKCE authentication script for Claude Code, following the same pattern as the existing `codex_auth.py` for OpenAI Codex CLI.

## Problem

Claude Code requires OAuth login via browser, which fails on headless/remote servers. This tool enables authentication by generating an auth URL the user can open on any device, then accepting the resulting authorization code to complete the token exchange.

## OAuth Parameters

| Parameter | Value |
|---|---|
| Auth endpoint | `https://claude.ai/oauth/authorize` |
| Token endpoint | `https://console.anthropic.com/v1/oauth/token` |
| Client ID | (set via `CLAUDE_CLIENT_ID` env var) |
| Redirect URI | `https://console.anthropic.com/oauth/code/callback` |
| Scopes | `org:create_api_key user:profile user:inference` |
| PKCE method | S256 |

## Credential Storage

- **Path:** `~/.claude/.credentials.json`
- **Permissions:** `0600`
- **Format:**

```json
{
  "claudeAiOauth": {
    "accessToken": "sk-ant-oat01-...",
    "refreshToken": "...",
    "expiresAt": 1800000000000
  }
}
```

`expiresAt` is a Unix timestamp in milliseconds, matching Claude Code's expected format.

## User Flow

1. Script generates PKCE code_verifier + code_challenge (S256).
2. Script builds and displays the authorization URL.
3. User opens URL in any browser, signs in with their Claude/Anthropic account.
4. Browser redirects to `https://console.anthropic.com/oauth/code/callback?code=...` which displays the authorization code on screen.
5. User copies the code (or the full callback URL) and pastes it into the terminal.
6. Script auto-detects whether input is a bare code or a full URL, extracts the code.
7. Script exchanges the code + code_verifier for access/refresh tokens.
8. Tokens are saved to `~/.claude/.credentials.json` with `0600` permissions.

## Key Difference from Codex Flow

Codex redirects to `http://localhost:1455/...` which fails (no local server). The user must copy the full URL from the browser address bar.

Claude redirects to `https://console.anthropic.com/oauth/code/callback` — a real server that displays the auth code. The user copies just the code (though pasting the full URL is also supported).

## Components

All in `claude_auth.py`, mirroring `codex_auth.py` structure:

- `generate_pkce_pair()` — generates S256 code_verifier and code_challenge
- `build_auth_url(code_challenge)` — builds Claude OAuth authorization URL, returns (url, state)
- `parse_callback_input(user_input)` — accepts a bare authorization code or full callback URL; extracts the code
- `exchange_code_for_tokens(code, code_verifier)` — POSTs to Claude token endpoint, returns token response dict
- `save_credentials(token_response, claude_home=None)` — writes `~/.claude/.credentials.json` in Claude Code's expected format
- `main()` — interactive CLI flow tying all components together

## Testing

`tests/test_claude_auth.py` covering:

- PKCE pair generation (format, length, S256 correctness)
- Auth URL construction (all params present and correct)
- Callback input parsing (bare code, full URL, URL with error, missing code)
- Credential saving (file format, permissions, backup behavior)
- Token exchange error handling (mocked)

## Files Changed

- `claude_auth.py` — new, main module
- `tests/test_claude_auth.py` — new, tests
- `README.md` — updated, add Claude section
