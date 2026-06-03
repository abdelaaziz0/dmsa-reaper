from __future__ import annotations

from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import AttributeChange, Operation
from dmsa_reaper.ops.operation_log import load_operation, save_operation
from dmsa_reaper.ops.verify import verify_operation_ldap, verify_operation_ldap_details

DMSA_DN = "CN=reaper-pwned-b105ec,OU=DMSACreate,OU=Reaper,DC=dmsalab,DC=local"
TARGET_DN = "CN=target.migrate,OU=Targets,OU=Reaper,DC=dmsalab,DC=local"


class _Attr:
    def __init__(self, values):
        self.values = values


class _Entry:
    def __init__(self, attrs: dict[str, list]):
        self._attrs = {key.lower(): (key, values) for key, values in attrs.items()}

    def __contains__(self, key):
        return key.lower() in self._attrs

    def __getitem__(self, key):
        values = self._attrs[key.lower()][1]
        return _Attr(values)


class _Conn:
    def __init__(self, values: dict[tuple[str, str], list], unreadable: set[tuple[str, str]] | None = None):
        self.values = {(dn.lower(), attr.lower()): vals for (dn, attr), vals in values.items()}
        self.unreadable = {
            (dn.lower(), attr.lower()) for dn, attr in (unreadable or set())
        }
        self.entries = []
        self.result = {"description": "success"}

    def search(self, search_base, search_filter, search_scope, attributes):
        attr = attributes[0]
        key = (search_base.lower(), attr.lower())
        if key in self.unreadable:
            self.entries = []
            self.result = {"description": "insufficientAccessRights"}
            return False
        if attr.lower() == "objectclass":
            exists = any(dn == search_base.lower() for dn, _ in self.values)
            self.entries = [_Entry({"objectClass": ["top"]})] if exists else []
            self.result = {"description": "success" if exists else "noSuchObject"}
            return exists
        if key in self.values:
            self.entries = [_Entry({attr: self.values[key]})]
            self.result = {"description": "success"}
            return True
        exists = any(dn == search_base.lower() for dn, _ in self.values)
        self.entries = [_Entry({})] if exists else []
        self.result = {"description": "success" if exists else "noSuchObject"}
        return exists


def _postpatch_op() -> Operation:
    return Operation(
        id="OP-0001",
        primitive="postpatch-mutual-pair",
        created_dns=[DMSA_DN],
        metadata={
            "created_dmsa_dn": DMSA_DN,
            "created_dmsa_sam": "reaper-pwned-b105ec$",
            "target_dn": TARGET_DN,
        },
        changed_attrs=[
            AttributeChange(
                dn=TARGET_DN,
                attribute="msDS-SupersededManagedAccountLink",
                before=None,
                after=[DMSA_DN],
                mode="replace",
                step_status="written",
            ),
            AttributeChange(
                dn=TARGET_DN,
                attribute="msDS-SupersededServiceAccountState",
                before=None,
                after=[2],
                mode="replace",
                step_status="written",
            ),
        ],
    )


def _conn_with_target_state(
    *,
    link_value=DMSA_DN,
    state_value="2",
    dmsa_attrs: bool = True,
    unreadable_dmsa_attrs: bool = False,
) -> _Conn:
    values = {
        (TARGET_DN, "msDS-SupersededManagedAccountLink"): [link_value],
        (TARGET_DN, "msDS-SupersededServiceAccountState"): [state_value],
        (DMSA_DN, "objectClass"): ["top"],
    }
    unreadable: set[tuple[str, str]] = set()
    if dmsa_attrs:
        values[(DMSA_DN, "msDS-ManagedAccountPrecededByLink")] = [TARGET_DN]
        values[(DMSA_DN, "msDS-DelegatedMSAState")] = ["2"]
    if unreadable_dmsa_attrs:
        unreadable.update({
            (DMSA_DN, "msDS-ManagedAccountPrecededByLink"),
            (DMSA_DN, "msDS-DelegatedMSAState"),
        })
    return _Conn(values, unreadable=unreadable)


def test_verify_succeeds_when_ldap_returns_string_for_expected_int():
    op = _postpatch_op()
    conn = _conn_with_target_state(state_value="2")

    assert verify_operation_ldap(op, conn=conn) is True
    assert op.metadata["ldap_verification"]["status"] == "verified"
    assert op.verified is True
    assert op.verified_ldap is True
    assert op.verified_external is False
    assert op.rollback_available is True
    assert op.ldap_verified_at is not None


def test_verify_succeeds_when_dn_casing_and_wrapping_differ():
    op = _postpatch_op()
    wrapped_lower_dn = (
        "<cn=reaper-pwned-b105ec, ou=dmsacreate, ou=reaper, "
        "dc=dmsalab, dc=local>"
    )
    conn = _conn_with_target_state(link_value=wrapped_lower_dn)

    assert verify_operation_ldap(op, conn=conn) is True
    assert op.metadata["ldap_verification"]["status"] == "verified"


def test_verify_reports_partial_when_created_dmsa_attrs_unreadable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ops_dir = tmp_path / "ops"
    op = _postpatch_op()
    save_operation(op, ops_dir=ops_dir)
    conn = _conn_with_target_state(dmsa_attrs=True, unreadable_dmsa_attrs=True)
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: conn)

    result = CliRunner().invoke(app, [
        "verify",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--mode", "ldap",
        "--domain", "dmsalab.local",
    ])

    assert result.exit_code == 0, result.output
    assert "mode=ldap verified=partial" in result.output
    assert "target-side verified=True" in result.output
    assert "created-objects verified=True" in result.output
    assert "msDS-ManagedAccountPrecededByLink" in result.output
    assert "unreadable" in result.output or "insufficientAccessRights" in result.output
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert stored.metadata["ldap_verification"]["status"] == "partial"


def test_verify_fails_when_target_side_after_values_do_not_match():
    op = _postpatch_op()
    conn = _conn_with_target_state(state_value="3", dmsa_attrs=False, unreadable_dmsa_attrs=True)

    details = verify_operation_ldap_details(op, conn=conn)

    assert details["status"] == "failed"
    assert details["target_side_verified"] is False
    assert any("msDS-SupersededServiceAccountState" in failure for failure in details["failures"])
