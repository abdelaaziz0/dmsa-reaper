from __future__ import annotations

from datetime import datetime, timezone

from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.ops import kerberos_diagnostics as kd
from dmsa_reaper.ops.kerberos_diagnostics import (
    DnsDiagnostics,
    KerberosDiagnostics,
    classify_ccache,
    inspect_dns_environment,
    inspect_kerberos_environment,
)


RUNNER = CliRunner()


def test_file_prefix_cache_emits_impacket_warning(tmp_path, monkeypatch):
    cache = tmp_path / "reaper.low.ccache"
    cache.write_bytes(b"cache")
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{cache}")

    diag = inspect_kerberos_environment(domain="dmsalab.local")

    assert diag.ccache_style == "file-prefix"
    assert diag.ccache_exists is True
    assert any("Impacket/NXC" in warning for warning in diag.warnings)
    assert "kerberos-cache-format" in diag.failure_classes


def test_raw_cache_path_accepted(tmp_path, monkeypatch):
    cache = tmp_path / "reaper.low.ccache"
    cache.write_bytes(b"cache")
    monkeypatch.setenv("KRB5CCNAME", str(cache))

    style, path, exists, warnings, failures = classify_ccache()

    assert style == "raw-file-path"
    assert path == str(cache)
    assert exists is True
    assert warnings == []
    assert failures == []


def test_missing_cache_warns(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)

    diag = inspect_kerberos_environment(domain="dmsalab.local")

    assert diag.ccache_style == "unset"
    assert diag.ccache_exists is False
    assert "kerberos-cache-format" in diag.failure_classes


def test_skew_above_300_seconds_warns(monkeypatch):
    dc_time = datetime(2026, 6, 3, 10, 0, tzinfo=timezone.utc)
    local_time = datetime(2026, 6, 3, 10, 10, tzinfo=timezone.utc)
    monkeypatch.setattr(kd, "_query_ntp_time", lambda _host: dc_time)

    diag = inspect_kerberos_environment(
        domain="dmsalab.local",
        dc_ip="192.168.56.10",
        local_time=local_time,
    )

    assert diag.time_skew_seconds == 600
    assert diag.time_skew_ok is False
    assert "kerberos-clock-skew" in diag.failure_classes


class _FailingResolver:
    nameservers = ["127.0.0.53"]

    def resolve(self, *_args, **_kwargs):
        raise kd.dns.resolver.NXDOMAIN()


def test_srv_dns_failure_reports_actionable_fix(monkeypatch):
    monkeypatch.setattr(kd.dns.resolver, "Resolver", lambda configure=True: _FailingResolver())

    diag = inspect_dns_environment(
        domain="dmsalab.local",
        dc_ip="192.168.56.10",
        dc_fqdn="DMSA.dmsalab.local",
    )

    assert diag.srv_lookup_ok is False
    assert diag.recommended_nameserver == "192.168.56.10"
    assert "kerberos-dns-resolution" in diag.failure_classes
    assert any("-ns 192.168.56.10" in warning for warning in diag.warnings)


def test_kerberos_doctor_json_contains_required_fields(tmp_path, monkeypatch):
    def fake_kerberos(**_kwargs):
        return KerberosDiagnostics(
            time_skew_seconds=14,
            time_skew_ok=True,
            krb5ccname="/workspace/reaper.low.ccache",
            ccache_style="raw-file-path",
            ccache_exists=True,
            tgt_present=True,
            cifs_ticket_present=True,
            imp_errata=["Impacket/NXC cache format OK: raw file path."],
        )

    def fake_dns(**_kwargs):
        return DnsDiagnostics(
            srv_lookup_ok=True,
            recommended_nameserver="192.168.56.10",
        )

    monkeypatch.setattr("dmsa_reaper.cli.inspect_kerberos_environment", fake_kerberos)
    monkeypatch.setattr("dmsa_reaper.cli.inspect_dns_environment", fake_dns)
    out = tmp_path / "doctor.json"

    result = RUNNER.invoke(app, [
        "kerberos-doctor",
        "--domain", "dmsalab.local",
        "--dc-ip", "192.168.56.10",
        "--json", str(out),
    ])

    assert result.exit_code == 0, result.output
    raw = out.read_text()
    assert '"time_skew_seconds": 14' in raw
    assert '"time_skew_ok": true' in raw
    assert '"krb5ccname": "/workspace/reaper.low.ccache"' in raw
    assert '"ccache_style": "raw-file-path"' in raw
    assert '"ccache_exists": true' in raw
    assert '"tgt_present": true' in raw
    assert '"cifs_ticket_present": true' in raw
    assert '"imp_errata"' in raw
    assert '"srv_lookup_ok": true' in raw
    assert '"recommended_nameserver": "192.168.56.10"' in raw
