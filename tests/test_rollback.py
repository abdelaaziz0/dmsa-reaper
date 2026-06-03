"""Tests for ops/rollback.py — rollback logic (without live LDAP)."""

from ldap3 import MODIFY_DELETE, MODIFY_REPLACE
from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import AttributeChange, Operation
from dmsa_reaper.ops.operation_log import load_operation, save_operation
from dmsa_reaper.ops.rollback import _attr_matches_value, rollback_operation


def _make_op(**kwargs) -> Operation:
    defaults = dict(id="OP-0001", primitive="postpatch-mutual-pair")
    defaults.update(kwargs)
    return Operation(**defaults)


def test_rollback_no_changes_marks_rolled_back():
    op = _make_op()
    result = rollback_operation(op, conn=None)
    # No changes, but conn is None — trivially safe even without conn.
    assert result.status == "rolled-back"


def test_rollback_with_changes_requires_ldap():
    op = _make_op(
        changed_attrs=[
            AttributeChange(dn="CN=x,DC=corp,DC=local", attribute="attr", before=None, after=["val"], mode="add")
        ]
    )
    result = rollback_operation(op, conn=None)
    assert result.status == "rollback-requires-ldap"


def test_rollback_not_available_flag():
    op = _make_op(rollback_available=False)
    result = rollback_operation(op, conn=None)
    assert result.status == "rollback-not-available"


class _Attr:
    def __init__(self, values):
        self.values = values


class _Entry:
    def __init__(self, attribute, values):
        self.attribute = attribute
        self._attr = _Attr(values)

    def __contains__(self, key):
        return key == self.attribute

    def __getitem__(self, key):
        if key != self.attribute:
            raise KeyError(key)
        return self._attr


class _Conn:
    def __init__(self, attribute, values):
        self.entries = [_Entry(attribute, values)]

    def search(self, **kwargs):
        return True


def test_rollback_verification_compares_typed_values_not_only_str():
    conn = _Conn("blob", [b"\x01"])

    assert _attr_matches_value(conn, "CN=x,DC=corp,DC=local", "blob", [b"\x01"])
    assert not _attr_matches_value(conn, "CN=x,DC=corp,DC=local", "blob", ["b'\\x01'"])


class _ObjectConn:
    def __init__(self, existing=None, fail_delete=False):
        self.objects = set(existing or [])
        self.deleted: list[str] = []
        self.entries = []
        self.fail_delete = fail_delete

    def search(self, search_base, **kwargs):
        self.entries = [_Entry("dn", [search_base])] if search_base in self.objects else []
        return True

    def delete(self, dn):
        if self.fail_delete:
            return False
        self.deleted.append(dn)
        self.objects.discard(dn)
        return True

    @property
    def result(self):
        return {"description": "mock"}


def test_rollback_deletes_existing_maybe_created_dn():
    dn = "CN=dmsarpr-ab12cd,OU=Reaper,DC=corp,DC=local"
    op = _make_op(maybe_created_dns=[dn], metadata={"created_dmsa_dn": dn})
    conn = _ObjectConn(existing={dn})

    result = rollback_operation(op, conn=conn)

    assert result.status == "rolled-back"
    assert dn in conn.deleted


def test_rollback_maybe_created_absent_is_success_with_warning():
    dn = "CN=dmsarpr-ab12cd,OU=Reaper,DC=corp,DC=local"
    op = _make_op(maybe_created_dns=[dn], metadata={"created_dmsa_dn": dn})
    conn = _ObjectConn(existing=set())

    result = rollback_operation(op, conn=conn)

    assert result.status == "rolled-back"
    assert result.recovery_notes


def test_rollback_partial_when_maybe_created_delete_fails():
    dn = "CN=dmsarpr-ab12cd,OU=Reaper,DC=corp,DC=local"
    op = _make_op(maybe_created_dns=[dn], metadata={"created_dmsa_dn": dn})
    conn = _ObjectConn(existing={dn}, fail_delete=True)

    result = rollback_operation(op, conn=conn)

    assert result.status == "rollback-partial"
    assert result.errors


class _ModifyConn:
    def __init__(self, *, fail_no_such_attribute=False):
        self.modified = []
        self.entries = [_Entry("attr", [])]
        self.fail_no_such_attribute = fail_no_such_attribute
        self.result = {"description": "success"}

    def modify(self, dn, changes):
        if self.fail_no_such_attribute:
            self.result = {"description": "noSuchAttribute"}
            return False
        self.modified.append((dn, changes))
        return True

    def search(self, search_base, **kwargs):
        self.entries = [_Entry("other", [])]
        return True


def test_rollback_ignores_no_such_attribute_for_absent_cleanup():
    op = _make_op(
        changed_attrs=[
            AttributeChange(
                dn="CN=x,DC=corp,DC=local",
                attribute="attr",
                before=None,
                after=["val"],
                mode="replace",
                step_status="written",
            )
        ]
    )
    conn = _ModifyConn(fail_no_such_attribute=True)

    result = rollback_operation(op, conn=conn)

    assert result.status == "rolled-back"


def test_rollback_skips_planned_unwritten_changes():
    op = _make_op(
        changed_attrs=[
            AttributeChange(
                dn="CN=x,DC=corp,DC=local",
                attribute="attr",
                before=None,
                after=["val"],
                mode="replace",
                step_status="planned",
            )
        ]
    )
    conn = _ModifyConn()

    result = rollback_operation(op, conn=conn)

    assert result.status == "rolled-back"
    assert conn.modified == []


def test_rollback_delete_failure_suggests_lookup_by_sam():
    dn = "CN=dmsa,OU=Reaper,DC=corp,DC=local"
    op = _make_op(created_dns=[dn], metadata={"created_dmsa_sam": "dmsa$"})
    conn = _ObjectConn(existing={dn}, fail_delete=True)

    result = rollback_operation(op, conn=conn)

    assert result.status == "rollback-partial"
    assert any("sAMAccountName dmsa$" in note for note in result.recovery_notes)


class _CaseEntry:
    def __init__(self, attrs):
        self.attrs = {key.lower(): _Attr(values) for key, values in attrs.items()}

    def __contains__(self, key):
        return key.lower() in self.attrs

    def __getitem__(self, key):
        return self.attrs[key.lower()]


class _LifecycleConn:
    def __init__(self, *, objects=None, attrs=None, delete_leaves_object=False):
        self.objects = {dn.lower(): dn for dn in (objects or [])}
        self.attrs = {
            (dn.lower(), attr.lower()): (attr, values)
            for (dn, attr), values in (attrs or {}).items()
        }
        self.delete_leaves_object = delete_leaves_object
        self.entries = []
        self.result = {"description": "success"}

    def search(self, search_base, search_filter="(objectClass=*)", search_scope=None, attributes=None):
        requested = (attributes or ["dn"])[0]
        dn_key = search_base.lower()
        if dn_key not in self.objects:
            self.entries = []
            self.result = {"description": "noSuchObject"}
            return False
        if requested.lower() in {"dn", "objectclass"}:
            self.entries = [_CaseEntry({requested: ["top"]})]
            self.result = {"description": "success"}
            return True
        attr_key = (dn_key, requested.lower())
        if attr_key in self.attrs:
            real_attr, values = self.attrs[attr_key]
            self.entries = [_CaseEntry({real_attr: values})]
        else:
            self.entries = [_CaseEntry({})]
        self.result = {"description": "success"}
        return True

    def modify(self, dn, changes):
        dn_key = dn.lower()
        self.objects.setdefault(dn_key, dn)
        for attr, operations in changes.items():
            for op_type, values in operations:
                key = (dn_key, attr.lower())
                if op_type == MODIFY_DELETE:
                    self.attrs.pop(key, None)
                elif op_type == MODIFY_REPLACE:
                    self.attrs[key] = (attr, values)
        self.result = {"description": "success"}
        return True

    def delete(self, dn):
        if not self.delete_leaves_object:
            self.objects.pop(dn.lower(), None)
            for key in list(self.attrs):
                if key[0] == dn.lower():
                    self.attrs.pop(key, None)
        self.result = {"description": "success"}
        return True


def _verified_rollback_op() -> Operation:
    return Operation(
        id="OP-0001",
        primitive="postpatch-mutual-pair",
        status="executed",
        created_dns=["CN=dmsa,OU=Reaper,DC=corp,DC=local"],
        verified=True,
        verified_ldap=True,
        metadata={
            "created_dmsa_sam": "dmsa$",
            "ldap_verification": {"status": "verified", "ok": True, "failures": []},
        },
        changed_attrs=[
            AttributeChange(
                dn="CN=target,DC=corp,DC=local",
                attribute="msDS-SupersededManagedAccountLink",
                before=None,
                after=["CN=dmsa,OU=Reaper,DC=corp,DC=local"],
                mode="replace",
                step_status="written",
            )
        ],
    )


def test_successful_rollback_preserves_historical_ldap_verification():
    op = _verified_rollback_op()
    conn = _LifecycleConn(
        objects=[
            "CN=dmsa,OU=Reaper,DC=corp,DC=local",
            "CN=target,DC=corp,DC=local",
        ],
        attrs={
            (
                "CN=target,DC=corp,DC=local",
                "msDS-SupersededManagedAccountLink",
            ): ["CN=dmsa,OU=Reaper,DC=corp,DC=local"]
        },
    )

    result = rollback_operation(op, conn=conn)

    assert result.status == "rolled-back"
    assert result.rollback_available is False
    assert result.rolled_back is True
    assert result.rollback_verified is True
    assert result.verified is False
    assert result.verified_ldap is True
    assert result.metadata["ldap_verification"]["ok"] is True
    assert result.metadata["rollback_verification"]["ok"] is True
    assert result.rolled_back_at is not None
    assert result.rollback_verified_at is not None


def test_second_rollback_cli_does_not_mutate_rolled_back_status(tmp_path, monkeypatch):
    ops_dir = tmp_path / "ops"
    op = _verified_rollback_op()
    op.status = "rolled-back"
    op.rollback_available = False
    op.rolled_back = True
    op.rollback_verified = True
    op.verified = False
    save_operation(op, ops_dir=ops_dir)

    def _fail_bind(_cfg):
        raise AssertionError("second rollback should not bind")

    monkeypatch.setattr("dmsa_reaper.cli.bind", _fail_bind)

    result = CliRunner().invoke(app, [
        "rollback",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--domain", "corp.local",
    ])

    assert result.exit_code == 0, result.output
    assert "operation already rolled back; rollback not available" in result.output
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert stored.status == "rolled-back"
    assert stored.rollback_verified is True
    assert stored.verified_ldap is True


def test_successful_rollback_cli_prints_previous_ldap_verification(tmp_path, monkeypatch):
    ops_dir = tmp_path / "ops"
    op = _verified_rollback_op()
    save_operation(op, ops_dir=ops_dir)
    conn = _LifecycleConn(
        objects=[
            "CN=dmsa,OU=Reaper,DC=corp,DC=local",
            "CN=target,DC=corp,DC=local",
        ],
        attrs={
            (
                "CN=target,DC=corp,DC=local",
                "msDS-SupersededManagedAccountLink",
            ): ["CN=dmsa,OU=Reaper,DC=corp,DC=local"]
        },
    )
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: conn)

    result = CliRunner().invoke(app, [
        "rollback",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--domain", "corp.local",
    ])

    assert result.exit_code == 0, result.output
    assert "status=rolled-back rollback_verified=true" in result.output
    assert "previous ldap verification=verified" in result.output
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert stored.status == "rolled-back"
    assert stored.metadata["rollback_verification"]["status"] == "verified"


def test_rollback_verification_failure_sets_explicit_status_and_notes():
    op = _verified_rollback_op()
    conn = _LifecycleConn(
        objects=[
            "CN=dmsa,OU=Reaper,DC=corp,DC=local",
            "CN=target,DC=corp,DC=local",
        ],
        attrs={
            (
                "CN=target,DC=corp,DC=local",
                "msDS-SupersededManagedAccountLink",
            ): ["CN=dmsa,OU=Reaper,DC=corp,DC=local"]
        },
        delete_leaves_object=True,
    )

    result = rollback_operation(op, conn=conn)

    assert result.status == "rollback-verify-failed"
    assert result.rollback_verified is False
    assert result.metadata["rollback_verification"]["ok"] is False
    assert result.recovery_notes
