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
