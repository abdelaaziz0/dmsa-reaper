from ldap3 import BASE, Connection


ROOTDSE_ATTRS = [
    "defaultNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "rootDomainNamingContext",
    "dnsHostName",
    "domainControllerFunctionality",
    "forestFunctionality",
    "domainFunctionality",
]


def _first(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else None
    return str(value)


def _get_case_insensitive(data: dict, key: str):
    if key in data:
        return data[key]
    key_l = key.lower()
    for k, v in data.items():
        if str(k).lower() == key_l:
            return v
    return None


def read_rootdse(conn: Connection) -> dict[str, str | None]:
    old_check_names = getattr(conn, "check_names", None)

    try:
        if old_check_names is not None:
            conn.check_names = False

        ok = conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["*", "+"],
        )

        if not ok:
            raise RuntimeError(f"RootDSE search failed: {conn.result}")

        entry = None
        for item in conn.response:
            if item.get("type") == "searchResEntry":
                entry = item
                break

        if entry is None:
            raise RuntimeError(f"RootDSE search returned no entry; result={conn.result}")

        data = entry.get("attributes", {}) or {}

        result = {
            attr: _first(_get_case_insensitive(data, attr))
            for attr in ROOTDSE_ATTRS
        }

        missing = [
            k for k in (
                "defaultNamingContext",
                "configurationNamingContext",
                "schemaNamingContext",
            )
            if not result.get(k)
        ]
        if missing:
            raise RuntimeError(
                "RootDSE missing required attributes: "
                + ", ".join(missing)
                + f"; returned keys={sorted(data.keys())}"
            )

        return result

    finally:
        if old_check_names is not None:
            conn.check_names = old_check_names
