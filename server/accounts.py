"""
Account rules — small enough to read in one sitting, which is deliberate.

Hierarchy (higher number = more authority):

    staff 1 < bursary 2 = department 2 = exams 2 = faculty 2
             < registry 3 < registrar 4 < admin 5

The rules that matter, and why:

  * You cannot create an account with more authority than your own. Otherwise a
    department officer can mint themselves a registrar account.
  * You cannot edit, disable, or reset anyone at your level or above. Otherwise
    two registrars can fight, and an admin can silently remove the Registrar.
  * You cannot disable or demote yourself — it locks the institution out.
  * Admins never choose another person's password. The server generates a
    temporary one; must_change_password forces a change at first sign-in, so the
    admin never knows the person's real password.
"""

from __future__ import annotations

import secrets
import sqlite3

HIERARCHY: dict[str, int] = {
    "staff": 1,
    "bursary": 2,
    "department": 2,
    "exams": 2,
    "faculty": 2,
    "registry": 3,
    "registrar": 4,
    "admin": 5,
}

# Which office kind an account role normally belongs to (used by the UI
# to suggest the right office when creating an account).
ROLE_OFFICE_KIND: dict[str, str | None] = {
    "admin": "registry",
    "registrar": "registry",
    "registry": "registry",
    "department": "department",
    "exams": "exams",
    "faculty": "faculty",
    "bursary": "bursary",
    "staff": None,
}

VALID_ROLES = tuple(HIERARCHY)


def rank(role: str | None) -> int:
    return HIERARCHY.get(role or "", 0)


def can_manage(actor_role: str | None, target_role: str | None) -> bool:
    """True when the actor outranks the target (strictly)."""
    return rank(actor_role) > rank(target_role)


def can_create(actor_role: str | None, new_role: str) -> bool:
    """You may only create accounts strictly below your own rank."""
    return new_role in HIERARCHY and rank(actor_role) > rank(new_role)


def generate_temp_password() -> str:
    """
    Readable but not guessable: three words-ish blocks of characters.
    Ambiguous characters (0/O, 1/l/I) are removed because these get read aloud
    over a phone or written on paper for a clerk.
    """
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "-".join(groups)          # e.g. K7QM-9XTA-3PHR


def office_label(conn: sqlite3.Connection, office_id: int | None) -> str | None:
    if not office_id:
        return None
    row = conn.execute("SELECT name FROM offices WHERE id = ?", (office_id,)).fetchone()
    return row["name"] if row else None
