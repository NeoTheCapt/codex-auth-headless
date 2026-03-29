# codex-auth-headless

OAuth PKCE authentication for [OpenAI Codex CLI](https://github.com/openai/codex) and [Claude Code](https://github.com/anthropics/claude-code) on headless/remote servers.

## Why?

Codex CLI and Claude Code require OAuth login via browser, which fails on headless servers (no GUI). This tool lets you:

1. Generate an authorization URL on the server
2. Open it in any browser (your laptop, phone, etc.)
3. Paste the authorization code (or callback URL) back to complete authentication

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/codex-auth-headless.git
cd codex-auth-headless

# No dependencies needed - uses Python standard library only

# Set up your Client IDs
cp .env.example .env
# Edit .env and fill in your Client IDs
```

**Requirements:** Python 3.7+

## Configuration

Client IDs are loaded from environment variables or a `.env` file:

```bash
# Option 1: .env file (recommended)
cp .env.example .env
# Edit .env with your Client IDs

# Option 2: Environment variables
export CODEX_CLIENT_ID=your_codex_client_id
export CLAUDE_CLIENT_ID=your_claude_client_id
```

## Usage: Codex CLI

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

## Usage: Claude Code

```bash
python claude_auth.py
```

The tool will:

1. Display an authorization URL
2. Ask you to open it in any browser and sign in with your Claude account
3. The browser will redirect to Anthropic's console which displays an authorization code
4. Copy the code (or the full callback URL) and paste it back into the terminal

Done! Credentials are saved to `~/.claude/.credentials.json` and Claude Code will work normally.

## Example Session: Codex

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

## Example Session: Claude Code

```
=== ClaudeAuthProxy ===
Headless OAuth authentication for Claude Code

Generating PKCE challenge...

Step 1: Open this URL in any browser and sign in with your Claude account:

  https://claude.ai/oauth/authorize?response_type=code&client_id=...

Step 2: After signing in, the browser will redirect to Anthropic's console
        which will display an authorization code.

Step 3: Copy the authorization code shown on the page.
        (You can also paste the full callback URL if you prefer)

Paste the authorization code (or callback URL) here: abc123xyz

Exchanging authorization code for tokens...

Success! Credentials saved to ~/.claude/.credentials.json
You can now use Claude Code normally.
```

## Security

- Uses PKCE (Proof Key for Code Exchange) - no client secrets stored
- Credentials saved with `0600` permissions (owner read/write only)
- State parameter validated to prevent CSRF attacks
- Existing `auth.json` backed up before overwriting

## How It Works

Both tools use the same OAuth PKCE flow pattern:

**Codex CLI** redirects to `localhost:1455` (which fails — user copies the URL).
**Claude Code** redirects to Anthropic's console (which displays the auth code).

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Headless       │     │  Your Browser    │     │  Auth Server    │
│  Server         │     │  (any device)    │     │  (OpenAI/       │
│                 │     │                  │     │   Anthropic)    │
└────────┬────────┘     └────────┬─────────┘     └────────┬────────┘
         │                       │                        │
         │ 1. Generate PKCE      │                        │
         │    + Auth URL         │                        │
         │──────────────────────>│                        │
         │                       │ 2. User signs in       │
         │                       │───────────────────────>│
         │                       │                        │
         │                       │ 3. Redirect with code  │
         │                       │<───────────────────────│
         │                       │                        │
         │ 4. User pastes        │                        │
         │<──────────────────────│                        │
         │    code / URL         │                        │
         │                       │                        │
         │ 5. Exchange code      │                        │
         │    for tokens         │                        │
         │───────────────────────────────────────────────>│
         │                       │                        │
         │ 6. Receive tokens     │                        │
         │<───────────────────────────────────────────────│
         │                       │                        │
         │ 7. Save credentials   │                        │
         │                       │                        │
```

## License

MIT
