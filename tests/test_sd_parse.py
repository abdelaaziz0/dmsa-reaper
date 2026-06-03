"""Tests for acl/parser.py — SD parse failure tracking vs. empty DACL."""

from types import SimpleNamespace

import pytest

from dmsa_reaper.acl.parser import parse_security_descriptor


def test_none_input_returns_empty_no_failure():
    psd = parse_security_descriptor(None)
    assert psd.owner_sid is None
    assert psd.aces == []
    assert not psd.parse_failed
    assert psd.parse_warnings == []


def test_empty_bytes_returns_empty_no_failure():
    psd = parse_security_descriptor(b"")
    assert not psd.parse_failed
    assert psd.aces == []


def test_malformed_blob_sets_parse_failed():
    psd = parse_security_descriptor(b"\xff\xfe\xfd")
    assert psd.parse_failed
    assert psd.parse_warnings
    assert any("parse" in w.lower() for w in psd.parse_warnings)


def test_malformed_blob_does_not_raise():
    try:
        parse_security_descriptor(b"\x00" * 4)
    except Exception as exc:
        pytest.fail(f"parse_security_descriptor raised unexpectedly: {exc}")


def test_parse_failed_distinct_from_empty_dacl(monkeypatch):
    """parse_failed=True must be distinguishable from a valid empty DACL."""
    import dmsa_reaper.acl.parser as parser_mod

    monkeypatch.setattr(
        parser_mod,
        "_try_parse_dacl",
        lambda raw: ([], ["DACL parse error: simulated failure"]),
    )

    psd_fail = parse_security_descriptor(b"\x01\x02\x03\x04")
    assert psd_fail.parse_failed
    assert psd_fail.parse_warnings

    monkeypatch.setattr(parser_mod, "_try_parse_dacl", lambda raw: ([], []))

    psd_empty = parse_security_descriptor(b"\x01\x02\x03\x04")
    assert not any("DACL" in w for w in psd_empty.parse_warnings)


def test_parse_warnings_populated_on_failure():
    psd = parse_security_descriptor(b"\xde\xad\xbe\xef\x00\x01\x02\x03")
    if psd.parse_failed:
        assert len(psd.parse_warnings) >= 1
        for w in psd.parse_warnings:
            assert isinstance(w, str)
            assert w


# ── per-ACE error surfacing ───────────────────────────────────────────────────

def test_malformed_dacl_ace_adds_parse_warning(monkeypatch):
    """A bad ACE inside a DACL must not be silently treated as an empty DACL.

    Fake SD uses the real impacket field layout:
        ace["AceType"], ace["AceFlags"], ace["Ace"]["Mask"]["Mask"], ace["Ace"]["Sid"]
    BadAce raises KeyError on the very first field access, which must surface as
    a parse_warning rather than being swallowed.
    """
    import dmsa_reaper.acl.parser as parser_mod

    class OwnerSid:
        def formatCanonical(self):
            return "S-1-5-21-X-500"

    class BadAce:
        def __getitem__(self, key):
            raise KeyError(f"missing {key}")

    class FakeSecurityDescriptor:
        def __init__(self, data):
            self.data = data

        def __getitem__(self, key):
            if key == "OwnerSid":
                return OwnerSid()
            if key == "Dacl":
                return {"Data": [BadAce()]}
            raise KeyError(key)

    monkeypatch.setattr(
        parser_mod,
        "ldaptypes",
        SimpleNamespace(SR_SECURITY_DESCRIPTOR=FakeSecurityDescriptor),
    )

    psd = parse_security_descriptor(b"fake-sd")

    assert psd.owner_sid == "S-1-5-21-X-500"
    assert psd.aces == []
    assert psd.parse_failed
    assert any("DACL ACE parse error" in w for w in psd.parse_warnings)


def test_unsupported_audit_ace_skips_without_warning(monkeypatch):
    """An audit/system ACE (type 0x02) must be skipped cleanly with no warning.

    The fake ACE uses the real impacket field layout: ace["AceType"] returns the
    type byte; once the parser sees it is not allow/deny, it returns immediately
    without touching any other fields.
    """
    import dmsa_reaper.acl.parser as parser_mod

    class FakeAuditAce:
        """Minimal fake that exposes only the fields read before the type-check returns."""
        def __getitem__(self, key):
            if key == "AceType":
                return 0x02  # SYSTEM_AUDIT_ACE — not allow or deny
            # Any other field access would indicate a parser bug.
            raise KeyError(f"unexpected field access on audit ACE: {key}")

    class FakeSecurityDescriptor:
        def __init__(self, data):
            pass

        def __getitem__(self, key):
            if key == "OwnerSid":
                return b""  # empty bytes → owner_sid=None, no error
            if key == "Dacl":
                return {"Data": [FakeAuditAce()]}
            raise KeyError(key)

    monkeypatch.setattr(
        parser_mod,
        "ldaptypes",
        SimpleNamespace(SR_SECURITY_DESCRIPTOR=FakeSecurityDescriptor),
    )

    psd = parse_security_descriptor(b"fake-sd")

    assert psd.aces == []
    assert not psd.parse_failed
    assert psd.parse_warnings == []


def test_inherit_only_ace_excluded(monkeypatch):
    """An inherit-only ACE must not appear in the parsed aces list for the current object."""
    import dmsa_reaper.acl.parser as parser_mod

    _INHERIT_ONLY_ACE = 0x08

    class FakeSid:
        def formatCanonical(self):
            return "S-1-5-21-X-1000"

    class FakeInner:
        def __getitem__(self, key):
            if key == "Mask":
                return {"Mask": 0x000f01ff}
            if key == "Sid":
                return FakeSid()
            raise KeyError(key)

    class FakeInheritOnlyAce:
        def __getitem__(self, key):
            if key == "AceType":
                return 0x00  # ACCESS_ALLOWED_ACE
            if key == "AceFlags":
                return _INHERIT_ONLY_ACE  # INHERIT_ONLY_ACE set
            if key == "Ace":
                return FakeInner()
            raise KeyError(key)

    class FakeSecurityDescriptor:
        def __init__(self, data):
            pass

        def __getitem__(self, key):
            if key == "OwnerSid":
                return b""  # no owner
            if key == "Dacl":
                return {"Data": [FakeInheritOnlyAce()]}
            raise KeyError(key)

    monkeypatch.setattr(
        parser_mod,
        "ldaptypes",
        SimpleNamespace(SR_SECURITY_DESCRIPTOR=FakeSecurityDescriptor),
    )

    psd = parse_security_descriptor(b"fake-sd")

    # Inherit-only ACE must not appear — it only applies to child objects.
    assert psd.aces == []
    assert not psd.parse_failed
    assert psd.parse_warnings == []
