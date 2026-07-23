from pathlib import Path


def test_readme_auth_claims_are_explicit_and_limited():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "password bind" in readme
    assert "LDAPS" in readme
    assert "SASL/GSSAPI" in readme
    assert "pass-the-hash" in readme
    assert "not yet supported consistently for ldap" in readme.lower()
    assert "ticket` runs Impacket's dMSA exchange" in readme


def test_readme_does_not_advertise_placeholder_security_checks():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "channel_binding_status" not in readme
    assert "placeholder/detected" not in readme


def test_docs_state_ldap_verification_is_not_kerberos_verification():
    readme = Path("README.md").read_text(encoding="utf-8")
    lab = Path("docs/LAB_VALIDATION.md").read_text(encoding="utf-8")

    assert "LDAP-state verification is not Kerberos verification" in readme
    assert "LDAP-state verification is not Kerberos verification" in lab
