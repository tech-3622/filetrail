"""
Password hashing and token helpers.

Design notes (worth defending in a viva, or to a Registrar):

* PBKDF2-HMAC-SHA256 with a per-user random salt. No external dependencies,
  so the university's ICT unit can audit every line.
* Iterations are stored *inside* the hash string, so we can raise the cost
  later without invalidating old passwords.
* password_hash format:  pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
* Verification uses hmac.compare_digest — constant time, so response timing
  does not leak how much of the password was correct.
* Session tokens are 256 bits from secrets.token_hex: not guessable, and
  compared by dictionary lookup (exact match) rather than by prefix.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 200_000          # ~100ms on modest hardware; tune to the server
SALT_BYTES = 16
SESSION_BYTES = 32            # 256-bit session token
SESSION_TTL_HOURS = 8         # a working day; not "remember me forever"


def hash_password(password: str, *, iterations: int = ITERATIONS) -> str:
    """Return a self-describing hash string. Never returns the password."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification. Returns False on any malformed input."""
    if not password or not stored:
        return False
    try:
        algorithm, iterations_s, salt_hex, digest_hex = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def new_session_token() -> str:
    return secrets.token_hex(SESSION_BYTES)


def new_csrf_token() -> str:
    return secrets.token_hex(16)


if __name__ == "__main__":
    # Smoke test: the hash must never contain the password, and must verify.
    h = hash_password("111111111")
    assert "111111111" not in h, "password leaked into hash string"
    assert verify_password("111111111", h)
    assert not verify_password("111111112", h)
    assert not verify_password("", h)
    print("security.py OK")
    print("example hash:", h[:60] + "...")
