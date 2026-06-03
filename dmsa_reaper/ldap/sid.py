from __future__ import annotations

from impacket.ldap.ldaptypes import LDAP_SID


def sid_to_sddl(value) -> str | None:
    """Convert any SID representation to a canonical SDDL string (S-1-...).

    Accepts bytes, bytearray, latin-1-encoded raw SID strings, canonical
    S-1-... strings, and None.  Returns None for a None input; returns a
    best-effort str for unparseable values rather than raising.
    """
    if value is None:
        return None

    if isinstance(value, str):
        if value.startswith("S-1-"):
            return value
        raw = value.encode("latin-1", errors="ignore")
    elif isinstance(value, bytes):
        raw = value
    elif isinstance(value, bytearray):
        raw = bytes(value)
    else:
        try:
            raw = bytes(value)
        except Exception:
            return str(value)

    try:
        sid = LDAP_SID()
        sid.fromString(raw)
        return sid.formatCanonical()
    except Exception:
        return str(value)


def entry_sid(attr) -> str | None:
    """Safely extract and normalize a SID from an ldap3 entry attribute.

    Tries ``attr.raw_values`` first (avoids ldap3 string coercion of binary
    SID bytes).  Falls back to ``attr.value`` when raw_values is absent or
    not a list/tuple — which makes this safe for test stubs that only expose
    a plain ``.value`` attribute, as well as MagicMock objects that would
    otherwise return truthy non-sequence values.
    """
    raw = None
    try:
        rvs = attr.raw_values
        if isinstance(rvs, (list, tuple)) and rvs:
            raw = rvs[0]
    except AttributeError:
        pass
    if raw is None:
        try:
            raw = attr.value
        except AttributeError:
            return None
    return sid_to_sddl(raw)
