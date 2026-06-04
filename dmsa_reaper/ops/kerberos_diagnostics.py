from __future__ import annotations

import os
import socket
import struct
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver


SKEW_LIMIT_SECONDS = 300


@dataclass
class KerberosDiagnostics:
    time_skew_seconds: int | None = None
    time_skew_ok: bool | None = None
    krb5_config: str | None = None
    realm: str | None = None
    domain_realm_ok: bool | None = None
    kdc_resolves: bool | None = None
    krb5ccname: str | None = None
    ccache_style: str = "unset"
    ccache_path: str | None = None
    ccache_exists: bool = False
    tgt_present: bool | None = None
    tgt_principal: str | None = None
    cifs_ticket_present: bool | None = None
    cifs_ticket_obtainable: bool | None = None
    cifs_ticket: str | None = None
    imp_errata: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    failure_classes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "time_skew_seconds": self.time_skew_seconds,
            "time_skew_ok": self.time_skew_ok,
            "krb5_config": self.krb5_config,
            "realm": self.realm,
            "domain_realm_ok": self.domain_realm_ok,
            "kdc_resolves": self.kdc_resolves,
            "krb5ccname": self.krb5ccname,
            "ccache_style": self.ccache_style,
            "ccache_path": self.ccache_path,
            "ccache_exists": self.ccache_exists,
            "tgt_present": self.tgt_present,
            "tgt_principal": self.tgt_principal,
            "cifs_ticket_present": self.cifs_ticket_present,
            "cifs_ticket_obtainable": self.cifs_ticket_obtainable,
            "cifs_ticket": self.cifs_ticket,
            "imp_errata": self.imp_errata,
            "warnings": self.warnings,
            "failure_classes": self.failure_classes,
        }


@dataclass
class DnsDiagnostics:
    dc_fqdn: str | None = None
    dc_resolves: bool | None = None
    dc_addresses: list[str] = field(default_factory=list)
    srv_record: str | None = None
    srv_lookup_ok: bool | None = None
    srv_records: list[str] = field(default_factory=list)
    resolver_nameservers: list[str] = field(default_factory=list)
    recommended_nameserver: str | None = None
    warnings: list[str] = field(default_factory=list)
    failure_classes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "dc_fqdn": self.dc_fqdn,
            "dc_resolves": self.dc_resolves,
            "dc_addresses": self.dc_addresses,
            "srv_record": self.srv_record,
            "srv_lookup_ok": self.srv_lookup_ok,
            "srv_records": self.srv_records,
            "resolver_nameservers": self.resolver_nameservers,
            "recommended_nameserver": self.recommended_nameserver,
            "warnings": self.warnings,
            "failure_classes": self.failure_classes,
        }


def classify_ccache(value: str | None = None) -> tuple[str, str | None, bool, list[str], list[str]]:
    raw = value if value is not None else os.environ.get("KRB5CCNAME")
    warnings: list[str] = []
    failure_classes: list[str] = []
    if not raw:
        warnings.append("KRB5CCNAME is unset; Kerberos cache checks cannot inspect a TGT.")
        failure_classes.append("kerberos-cache-format")
        return "unset", None, False, warnings, failure_classes

    style = "raw-file-path"
    path: str | None = raw
    if raw.startswith("FILE:"):
        style = "file-prefix"
        path = raw[5:]
        warnings.append(
            "FILE: prefix works with MIT krb5 tools but may fail with Impacket/NXC in this "
            "Exegol environment; use a raw cache path for Impacket-like tools."
        )
        failure_classes.append("kerberos-cache-format")
    elif raw.startswith("DIR:"):
        style = "dir"
        path = raw[4:]
        warnings.append("DIR: caches are accepted by MIT krb5 but may not work with Impacket/NXC.")
        failure_classes.append("kerberos-cache-format")
    elif raw.startswith("KEYRING:"):
        style = "keyring"
        path = None
        warnings.append("KEYRING: caches are not portable to Impacket/NXC; export a file cache.")
        failure_classes.append("kerberos-cache-format")
    elif ":" in raw and not raw.startswith("/"):
        style = raw.split(":", 1)[0].lower()
        path = raw.split(":", 1)[1] or None
        warnings.append(f"KRB5CCNAME style {style!r} may not be supported by Impacket/NXC.")
        failure_classes.append("kerberos-cache-format")

    exists = bool(path and Path(path).exists())
    if path and not exists:
        warnings.append(f"Kerberos cache path does not exist: {path}")
        failure_classes.append("kerberos-cache-format")
    return style, path, exists, warnings, failure_classes


def _query_ntp_time(host: str, timeout: float = 2.0) -> datetime | None:
    packet = b"\x1b" + (47 * b"\0")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, 123))
        data, _ = sock.recvfrom(48)
    if len(data) < 48:
        return None
    seconds = struct.unpack("!I", data[40:44])[0]
    # NTP epoch starts 1900-01-01; Unix epoch starts 1970-01-01.
    unix_seconds = seconds - 2_208_988_800
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)


def _parse_krb5_domain_realm(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    current_section: str | None = None
    mappings: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]").strip().lower()
            continue
        if current_section == "domain_realm" and "=" in line:
            key, value = line.split("=", 1)
            mappings[key.strip().lower()] = value.strip()
    return mappings


def _inspect_klist(ccache: str | None, service: str | None) -> tuple[bool | None, str | None, bool | None, str | None, list[str]]:
    if not ccache:
        return None, None, None, None, ["KRB5CCNAME is unset."]
    env = os.environ.copy()
    env["KRB5CCNAME"] = ccache
    try:
        proc = subprocess.run(["klist", "-e"], capture_output=True, text=True, env=env, timeout=5)
    except FileNotFoundError:
        return None, None, None, None, ["klist is not installed; cache contents not inspected."]
    except subprocess.SubprocessError as exc:
        return None, None, None, None, [f"klist failed: {exc}"]
    if proc.returncode != 0:
        return False, None, False, None, ["klist could not read the Kerberos cache."]
    principal: str | None = None
    for line in proc.stdout.splitlines():
        if line.startswith("Default principal:"):
            principal = line.split(":", 1)[1].strip()
            break
    service_present: bool | None = None
    service_match: str | None = None
    if service:
        target = service.lower()
        service_present = False
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if target in stripped.lower():
                service_present = True
                service_match = stripped.split()[0] if stripped else stripped
                break
    return principal is not None, principal, service_present, service_match, []


def _try_kvno(ccache: str | None, service: str) -> tuple[bool | None, list[str]]:
    if not ccache:
        return None, ["KRB5CCNAME is unset; kvno was not attempted."]
    env = os.environ.copy()
    env["KRB5CCNAME"] = ccache
    try:
        proc = subprocess.run(["kvno", service], capture_output=True, text=True, env=env, timeout=8)
    except FileNotFoundError:
        return None, ["kvno is not installed; CIFS service ticket obtainability was not tested."]
    except subprocess.SubprocessError as exc:
        return None, [f"kvno failed: {exc}"]
    if proc.returncode == 0:
        return True, []
    stderr = proc.stderr.strip().splitlines()
    detail = stderr[-1] if stderr else "unknown error"
    return False, [f"kvno could not obtain {service}: {detail}"]


def inspect_kerberos_environment(
    *,
    domain: str,
    dc_ip: str | None = None,
    dc_host: str | None = None,
    dc_fqdn: str | None = None,
    run_cache_checks: bool = False,
    attempt_cifs_ticket: bool = False,
    local_time: datetime | None = None,
) -> KerberosDiagnostics:
    diag = KerberosDiagnostics()
    diag.krb5_config = os.environ.get("KRB5_CONFIG") or "/etc/krb5.conf"
    diag.krb5ccname = os.environ.get("KRB5CCNAME")
    diag.realm = domain.upper()

    style, path, exists, warnings, failure_classes = classify_ccache(diag.krb5ccname)
    diag.ccache_style = style
    diag.ccache_path = path
    diag.ccache_exists = exists
    diag.warnings.extend(warnings)
    diag.failure_classes.extend(failure_classes)
    if style == "raw-file-path":
        diag.imp_errata.append("Impacket/NXC cache format OK: raw file path.")
    elif style == "file-prefix":
        diag.imp_errata.append(
            "MIT tools accept FILE:<path>, but Impacket/NXC may require the raw path."
        )
        diag.imp_errata.append(
            f"Recommendation: export KRB5CCNAME={path}" if path else "Export KRB5CCNAME as a raw file path."
        )

    krb5_path = Path(diag.krb5_config)
    if krb5_path.exists():
        try:
            mappings = _parse_krb5_domain_realm(krb5_path)
            expected = domain.upper()
            domain_keys = {domain.lower(), f".{domain.lower()}"}
            mapped = [mappings[key] for key in domain_keys if key in mappings]
            diag.domain_realm_ok = not mapped or any(value.upper() == expected for value in mapped)
            if diag.domain_realm_ok is False:
                diag.warnings.append(f"krb5 domain_realm does not map {domain} to {expected}.")
        except OSError as exc:
            diag.domain_realm_ok = None
            diag.warnings.append(f"Could not read krb5 config {krb5_path}: {exc}")
    else:
        diag.domain_realm_ok = None
        diag.warnings.append(f"Kerberos config not found: {krb5_path}")

    kdc_name = dc_fqdn or dc_host or dc_ip
    if kdc_name:
        try:
            socket.getaddrinfo(kdc_name, 88)
            diag.kdc_resolves = True
        except socket.gaierror:
            diag.kdc_resolves = False
            diag.warnings.append(f"KDC host does not resolve: {kdc_name}")
            diag.failure_classes.append("kerberos-dns-resolution")

    if dc_ip:
        try:
            dc_time = _query_ntp_time(dc_ip)
        except OSError as exc:
            dc_time = None
            diag.warnings.append(f"Could not query DC time over NTP: {exc}")
        if dc_time is not None:
            now = local_time or datetime.now(timezone.utc)
            diag.time_skew_seconds = int((now - dc_time).total_seconds())
            diag.time_skew_ok = abs(diag.time_skew_seconds) <= SKEW_LIMIT_SECONDS
            if not diag.time_skew_ok:
                diag.warnings.append(
                    f"Kerberos clock skew is {diag.time_skew_seconds}s; keep clocks within "
                    f"{SKEW_LIMIT_SECONDS}s."
                )
                diag.failure_classes.append("kerberos-clock-skew")

    if run_cache_checks:
        service = f"cifs/{dc_fqdn}@{domain.upper()}" if dc_fqdn else None
        tgt_present, principal, cifs_present, cifs_ticket, klist_warnings = _inspect_klist(
            diag.krb5ccname, service
        )
        diag.tgt_present = tgt_present
        diag.tgt_principal = principal
        diag.cifs_ticket_present = cifs_present
        diag.cifs_ticket = cifs_ticket
        diag.warnings.extend(klist_warnings)
        if (
            attempt_cifs_ticket
            and service
            and cifs_present is False
            and diag.ccache_exists
        ):
            obtainable, kvno_warnings = _try_kvno(diag.krb5ccname, service)
            diag.cifs_ticket_obtainable = obtainable
            diag.warnings.extend(kvno_warnings)
            if obtainable is True:
                diag.cifs_ticket_present = True
                diag.cifs_ticket = service
            elif obtainable is False:
                diag.failure_classes.append("kerberos-tooling-inconclusive")

    return diag


def inspect_dns_environment(
    *,
    domain: str,
    dc_ip: str | None = None,
    dc_fqdn: str | None = None,
) -> DnsDiagnostics:
    diag = DnsDiagnostics(dc_fqdn=dc_fqdn)
    resolver = dns.resolver.Resolver(configure=True)
    diag.resolver_nameservers = [str(nameserver) for nameserver in resolver.nameservers]
    if dc_ip:
        diag.recommended_nameserver = dc_ip

    if dc_fqdn:
        try:
            answers = resolver.resolve(dc_fqdn, "A")
            diag.dc_addresses = [answer.to_text() for answer in answers]
            diag.dc_resolves = bool(diag.dc_addresses)
        except dns.exception.DNSException as exc:
            diag.dc_resolves = False
            diag.warnings.append(f"DC FQDN resolution failed for {dc_fqdn}: {exc}")
            diag.failure_classes.append("kerberos-dns-resolution")

    srv_name = f"_ldap._tcp.pdc._msdcs.{domain}".rstrip(".")
    diag.srv_record = srv_name
    try:
        answers = resolver.resolve(srv_name, "SRV")
        diag.srv_records = [answer.to_text() for answer in answers]
        diag.srv_lookup_ok = bool(diag.srv_records)
    except dns.exception.DNSException as exc:
        diag.srv_lookup_ok = False
        diag.failure_classes.append("kerberos-dns-resolution")
        nameservers = ", ".join(diag.resolver_nameservers) or "unknown resolver"
        if "127.0.0.53" in diag.resolver_nameservers:
            diag.warnings.append(
                f"SRV lookup failed through systemd-resolved ({nameservers}); use the DC as DNS resolver."
            )
        else:
            diag.warnings.append(f"SRV lookup failed through {nameservers}: {exc}")
        if dc_ip:
            diag.warnings.append(
                f"BloodHound.py: use -ns {dc_ip} and -dc {dc_fqdn or dc_ip}, or update /etc/resolv.conf."
            )
    return diag
