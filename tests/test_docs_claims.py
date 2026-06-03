from pathlib import Path


def test_readme_auth_claims_are_explicit_and_limited():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "password bind" in readme
    assert "LDAPS" in readme
    assert "environment Kerberos through ldap3 SASL/GSSAPI" in readme
    assert "robust Impacket-style pass-the-hash" in readme
    assert "native Kerberos ticket handling" in readme


def test_readme_documents_channel_binding_placeholders():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "channel_binding_status" in readme
    assert "placeholders" in readme
    assert "unknown" in readme


def test_docs_state_ldap_verification_is_not_kerberos_verification():
    readme = Path("README.md").read_text(encoding="utf-8")
    lab = Path("docs/LAB_VALIDATION.md").read_text(encoding="utf-8")

    assert "LDAP-state verification is not Kerberos verification" in readme
    assert "LDAP-state verification is not Kerberos verification" in lab
