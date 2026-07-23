from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from dmsa_reaper.models import Operation
from dmsa_reaper.ops import ticket


class _Principal:
    def __init__(self, value: str):
        self.value = value

    def prettyPrint(self):
        return self.value.encode()


def _fake_cache(client: str, service: str, endtime: int):
    credential = {
        "client": _Principal(client),
        "server": _Principal(service),
        "time": {"endtime": endtime},
    }
    return SimpleNamespace(credentials=[credential])


def test_validate_ccache_binds_client_service_and_freshness(tmp_path, monkeypatch):
    path = tmp_path / "ticket.ccache"
    path.write_bytes(b"valid-placeholder")
    monkeypatch.setattr(
        ticket.CCache,
        "loadFile",
        lambda _path: _fake_cache(
            "dmsarpr-123$@CORP.LOCAL",
            "cifs/dc01.corp.local@CORP.LOCAL",
            int(time.time()) + 3600,
        ),
    )

    result = ticket.validate_ccache(
        path,
        expected_client="dmsarpr-123$",
        expected_service="cifs/dc01.corp.local",
        created_after=path.stat().st_mtime - 1,
    )

    assert result["client"] == "dmsarpr-123$@CORP.LOCAL"
    assert result["services"] == ["cifs/dc01.corp.local@CORP.LOCAL"]


def test_validate_ccache_rejects_wrong_client_even_when_parse_succeeds(tmp_path, monkeypatch):
    path = tmp_path / "ticket.ccache"
    path.write_bytes(b"valid-placeholder")
    monkeypatch.setattr(
        ticket.CCache,
        "loadFile",
        lambda _path: _fake_cache(
            "operator@CORP.LOCAL",
            "krbtgt/CORP.LOCAL@CORP.LOCAL",
            int(time.time()) + 3600,
        ),
    )

    with pytest.raises(ticket.TicketAcquisitionError, match="does not match created dMSA"):
        ticket.validate_ccache(
            path,
            expected_client="dmsarpr-123$",
            expected_service="krbtgt/corp.local",
            created_after=path.stat().st_mtime - 1,
        )


def _operation() -> Operation:
    return Operation(
        id="OP-0001",
        primitive="postpatch-mutual-pair",
        status="executed",
        verified_ldap=True,
        metadata={
            "created_dmsa_sam": "dmsarpr-123$",
            "target_dn": "CN=Administrator,DC=corp,DC=local",
            "dc_host": "dc01.corp.local",
        },
    )


def test_native_ticket_stage_writes_private_handoff_artifacts(tmp_path, monkeypatch):
    source = tmp_path / "operator.ccache"
    source.write_bytes(b"source")

    def fake_run(_executable, _args, *, cwd, ccache):
        del ccache
        (cwd / "impacket-output.ccache").write_bytes(b"ticket")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_validate(path, *, expected_client, expected_service, created_after):
        del path, created_after
        return {
            "client": f"{expected_client}@CORP.LOCAL",
            "services": [f"{expected_service}@CORP.LOCAL"],
            "expires_at": "2099-01-01T00:00:00Z",
            "size": 6,
        }

    monkeypatch.setattr(ticket, "_run_getst", fake_run)
    monkeypatch.setattr(ticket, "validate_ccache", fake_validate)

    result = ticket.acquire_dmsa_ticket(
        _operation(),
        source_ccache=source,
        identity="operator",
        domain="corp.local",
        service="cifs/dc01.corp.local",
        dc_ip="10.0.0.10",
        runs_dir=tmp_path / "runs",
        getst_executable="/fake/getST.py",
    )

    for key in ("tgt_ccache", "service_ccache"):
        artifact = Path(result[key])
        assert artifact.is_file()
        assert artifact.stat().st_mode & 0o777 == 0o600
    script = Path(result["use_script"])
    assert script.is_file()
    assert script.stat().st_mode & 0o777 == 0o700
    assert "KRB5CCNAME" in script.read_text(encoding="utf-8")
    assert (tmp_path / "runs" / "OP-0001" / "summary.json").stat().st_mode & 0o777 == 0o600


def test_exit_zero_without_ccache_is_not_proof(tmp_path, monkeypatch):
    source = tmp_path / "operator.ccache"
    source.write_bytes(b"source")
    monkeypatch.setattr(
        ticket,
        "_run_getst",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    with pytest.raises(ticket.TicketAcquisitionError, match="found 0"):
        ticket.acquire_dmsa_ticket(
            _operation(),
            source_ccache=source,
            identity="operator",
            domain="corp.local",
            service="cifs/dc01.corp.local",
            runs_dir=tmp_path / "runs",
            getst_executable="/fake/getST.py",
        )


def test_ticket_stage_requires_ldap_verification(tmp_path):
    operation = _operation()
    operation.verified_ldap = False
    source = tmp_path / "operator.ccache"
    source.write_bytes(b"source")

    with pytest.raises(ticket.TicketAcquisitionError, match="LDAP relationship"):
        ticket.acquire_dmsa_ticket(
            operation,
            source_ccache=source,
            identity="operator",
            domain="corp.local",
            service="cifs/dc01.corp.local",
            runs_dir=tmp_path / "runs",
            getst_executable="/fake/getST.py",
        )
