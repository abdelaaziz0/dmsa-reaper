from __future__ import annotations

def ldaps_hint(use_ldaps: bool) -> str:
    return "LDAPS enabled" if use_ldaps else "LDAP enabled"
