# codex-auth-headless

OAuth PKCE authentication for [OpenAI Codex CLI](https://github.com/openai/codex) on headless/remote servers.

## Why?

Codex CLI requires OAuth login via browser, which fails on headless servers (no GUI). This tool lets you:

1. Generate an authorization URL on the server
2. Open it in any browser (your laptop, phone, etc.)
3. Paste the callback URL back to complete authentication

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/codex-auth-headless.git
cd codex-auth-headless

# No dependencies needed - uses Python standard library only
python codex_auth.py
```

**Requirements:** Python 3.7+

## Usage

```bash
python codex_auth.py
```

The tool will:

1. Display an authorization URL
2. Ask you to open it in any browser and sign in with your ChatGPT account
3. The browser will redirect to `localhost:1455` and fail (expected!)
4. Copy the full URL from the browser's address bar
5. Paste it back into the terminal

Done! Credentials are saved to `~/.codex/auth.json` and Codex CLI will work normally.

## Example Session

```
=== CodexAuthProxy ===
Headless OAuth authentication for OpenAI Codex CLI

Generating PKCE challenge...

Step 1: Open this URL in any browser and sign in with ChatGPT:

  https://auth.openai.com/oauth/authorize?response_type=code&client_id=...

Step 2: After signing in, the browser will try to redirect to
        localhost:1455 and FAIL. That's expected!

Step 3: Copy the FULL URL from the browser's address bar
        (it starts with http://localhost:1455/auth/callback?...)

Paste the callback URL here: http://localhost:1455/auth/callback?code=xxx&state=yyy

Exchanging authorization code for tokens...

Success! Credentials saved to ~/.codex/auth.json
You can now use `codex` normally.
```

## Security

- Uses PKCE (Proof Key for Code Exchange) - no client secrets stored
- Credentials saved with `0600` permissions (owner read/write only)
- State parameter validated to prevent CSRF attacks
- Existing `auth.json` backed up before overwriting

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Headless       │     │  Your Browser    │     │  OpenAI Auth    │
│  Server         │     │  (any device)    │     │  Server         │
└────────┬────────┘     └────────┬─────────┘     └────────┬────────┘
         │                       │                        │
         │ 1. Generate PKCE      │                        │
         │    + Auth URL         │                        │
         │──────────────────────>│                        │
         │                       │ 2. User signs in       │
         │                       │───────────────────────>│
         │                       │                        │
         │                       │ 3. Redirect to         │
         │                       │<───────────────────────│
         │                       │    localhost (fails)   │
         │                       │                        │
         │ 4. User pastes        │                        │
         │<──────────────────────│                        │
         │    callback URL       │                        │
         │                       │                        │
         │ 5. Exchange code      │                        │
         │    for tokens         │                        │
         │───────────────────────────────────────────────>│
         │                       │                        │
         │ 6. Receive tokens     │                        │
         │<───────────────────────────────────────────────│
         │                       │                        │
         │ 7. Save to            │                        │
         │    ~/.codex/auth.json │                        │
         │                       │                        │
```

## License

MIT
