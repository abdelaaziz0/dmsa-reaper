from __future__ import annotations

from dataclasses import dataclass

from ldap3 import NONE, NTLM, SASL, KERBEROS, Connection, Server, Tls


@dataclass
class LdapAuthConfig:
    domain: str
    dc_ip: str | None = None
    dc_host: str | None = None
    username: str | None = None
    password: str | None = None
    kerberos: bool = False
    use_ldaps: bool = False
    port: int | None = None
    timeout: int = 10
    tls_validate: bool = False


class LdapBindError(RuntimeError):
    pass


def build_server(config: LdapAuthConfig) -> Server:
    host = config.dc_host or config.dc_ip or config.domain
    port = config.port or (636 if config.use_ldaps else 389)
    tls = Tls(validate=0) if config.use_ldaps and not config.tls_validate else None

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
        tls=tls,
    )


def bind(config: LdapAuthConfig) -> Connection:
    server = build_server(config)

    common_kwargs = {
        "auto_bind": False,
        "check_names": False,
        "raise_exceptions": False,
    }

    if config.kerberos:
        conn = Connection(
            server,
            authentication=SASL,
            sasl_mechanism=KERBEROS,
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
            **common_kwargs,
        )
    else:
        conn = Connection(server, **common_kwargs)

    if not conn.bind():
        raise LdapBindError(f"LDAP bind failed: {conn.result}")

    return conn
