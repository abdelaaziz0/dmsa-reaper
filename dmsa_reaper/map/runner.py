from __future__ import annotations

from dmsa_reaper.auth.ldap_bind import LdapAuthConfig, bind
from dmsa_reaper.constants import DEFAULT_SD_FLAGS
from dmsa_reaper.ldap.rootdse import read_rootdse
from dmsa_reaper.map.containers import enumerate_containers
from dmsa_reaper.map.dmsa_objects import enumerate_dmsas
from dmsa_reaper.map.environment import build_environment
from dmsa_reaper.map.principal import get_current_principal
from dmsa_reaper.map.targets import enumerate_targets
from dmsa_reaper.models import MapState
from dmsa_reaper.schema.resolver import SchemaResolver


def run_live_map(
    config: LdapAuthConfig,
    sdflags: int = DEFAULT_SD_FLAGS,
    *,
    target_filter: str | None = None,
    container_filter: str | None = None,
    max_targets: int | None = None,
    only_current_principal: bool = False,
) -> MapState:
    conn = bind(config)
    root = read_rootdse(conn)
    schema_nc = root["schemaNamingContext"]
    config_nc = root["configurationNamingContext"]
    default_nc = root["defaultNamingContext"]
    if not schema_nc or not config_nc or not default_nc:
        raise RuntimeError("RootDSE missing required naming contexts")

    schema_cache = SchemaResolver(conn, schema_nc).resolve()
    env = build_environment(conn, config.domain, schema_cache)
    env.mapped_dc_host = config.dc_host
    env.mapped_dc_ip = config.dc_ip

    principal = get_current_principal(conn, default_nc, config.username)

    dmsas = enumerate_dmsas(conn, default_nc, sdflags, principal, schema_cache)
    containers = enumerate_containers(
        conn,
        default_nc,
        sdflags,
        principal,
        schema_cache,
        container_filter=container_filter,
    )
    targets = enumerate_targets(
        conn,
        default_nc,
        sdflags,
        principal,
        schema_cache,
        target_filter=target_filter,
        max_targets=max_targets,
        only_current_principal=only_current_principal,
    )

    return MapState(
        environment=env,
        schema_cache=schema_cache,
        current_principal=principal,
        dmsas=dmsas,
        containers=containers,
        targets=targets,
    )
