from __future__ import annotations

from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Connection

MODES = {
    "add": MODIFY_ADD,
    "replace": MODIFY_REPLACE,
    "delete": MODIFY_DELETE,
}


def modify_attribute(conn: Connection, dn: str, attribute: str, values, mode: str = "replace") -> None:
    if mode not in MODES:
        raise ValueError(f"unsupported modify mode: {mode}")
    if not conn.modify(dn, {attribute: [(MODES[mode], values)]}):
        raise RuntimeError(f"LDAP modify failed for {dn} {attribute}: {conn.result}")


def add_object(conn: Connection, dn: str, object_classes: list[str], attributes: dict) -> None:
    if not conn.add(dn, object_class=object_classes, attributes=attributes):
        raise RuntimeError(f"LDAP add failed for {dn}: {conn.result}")


def delete_object(conn: Connection, dn: str) -> None:
    if not conn.delete(dn):
        raise RuntimeError(f"LDAP delete failed for {dn}: {conn.result}")
