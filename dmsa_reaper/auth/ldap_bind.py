from __future__ import annotations

from dataclasses import dataclass
import ssl

from ldap3 import (
    NONE,
    NTLM,
    SASL,
    KERBEROS,
    ENCRYPT,
    Connection,
    Server,
    Tls,
)

@dataclass
class LdapAuthConfig:
    domain: str
    dc_ip: str | None = None
    dc_host: str | None = None
    username: str | None = None
    password: str | None = None
    kerberos: bool = False
    use_ldaps: bool = False
    start_tls: bool = False
    port: int | None = None
    timeout: int = 10
    tls_validate: bool = False


class LdapBindError(RuntimeError):
    pass


def build_server(config: LdapAuthConfig) -> Server:
    # Keep --dc-ip as the network endpoint when both values are supplied.
    # --dc-host remains the Kerberos service hostname below.
    host = config.dc_ip or config.dc_host or config.domain
    port = config.port or (636 if config.use_ldaps else 389)
    tls = Tls(validate=ssl.CERT_REQUIRED if config.tls_validate else ssl.CERT_NONE)

    # Important:
    # Do NOT load server schema here.
    # ldap3 schema/name validation breaks on AD RootDSE operational attrs
    # and newer/preview schema attrs. We want the DC to answer, not ldap3
    # to reject attributes client-side.
    return Server(
        host,
        port=port,
        use_ssl=config.use_ldaps,
        get_info=NONE,
        connect_timeout=config.timeout,
        tls=tls if (config.use_ldaps or config.start_tls) else None,
    )


def bind(config: LdapAuthConfig) -> Connection:
    if config.use_ldaps and config.start_tls:
        raise LdapBindError("LDAPS and STARTTLS are mutually exclusive")

    server = build_server(config)

    common_kwargs = {
        "auto_bind": False,
        "check_names": False,
        "raise_exceptions": False,
    }

    # LDAP signing/sealing when TLS is not active.
    security_kwargs = {}

    if not config.use_ldaps and not config.start_tls:
        security_kwargs["session_security"] = ENCRYPT

    if config.kerberos:
        conn = Connection(
            server,
            authentication=SASL,
            sasl_mechanism=KERBEROS,
            **security_kwargs,
            **common_kwargs,
        )

    elif config.username:
        user = config.username

        if "\\" not in user and "@" not in user and config.domain:
            user = f"{config.domain}\\{user}"

        conn = Connection(
            server,
            user=user,
            password=config.password or "",
            authentication=NTLM,
            **security_kwargs,
            **common_kwargs,
        )

    else:
        conn = Connection(
            server,
            **common_kwargs,
        )

    if config.start_tls:
        if not conn.open():
            raise LdapBindError(
                f"LDAP connection failed before STARTTLS: {conn.result}"
            )

        if not conn.start_tls():
            raise LdapBindError(f"LDAP STARTTLS failed: {conn.result}")

    if not conn.bind():
        raise LdapBindError(f"LDAP bind failed: {conn.result}")

    return conn
