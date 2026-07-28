from __future__ import annotations

from ldap3 import Connection

from dmsa_reaper.constants import DMSA_CLASS, DMSA_RELEVANT_ATTRS, FALLBACK_GUIDS
from dmsa_reaper.models import SchemaCache
from dmsa_reaper.schema.guids import decode_schema_guid


class SchemaResolver:
    def __init__(self, conn: Connection, schema_nc: str):
        self.conn = conn
        self.schema_nc = schema_nc

    def resolve(self) -> SchemaCache:
        cache = SchemaCache()
        dmsa_guid = self._resolve_class_guid(DMSA_CLASS)
        if dmsa_guid:
            cache.dmsa_class_guid = dmsa_guid
            cache.dmsa_class_guid_resolved = True
        elif DMSA_CLASS in FALLBACK_GUIDS:
            cache.dmsa_class_guid = FALLBACK_GUIDS[DMSA_CLASS]

        for attr in DMSA_RELEVANT_ATTRS:
            guid = self._resolve_attr(attr)
            if guid:
                cache.attr_guids[attr] = guid
            elif attr in FALLBACK_GUIDS:
                cache.attr_guids[attr] = FALLBACK_GUIDS[attr]

        return cache

    def _resolve_class_guid(self, ldap_display_name: str) -> str | None:
        self.conn.search(
            search_base=self.schema_nc,
            search_filter=f"(&(objectClass=classSchema)(ldapDisplayName={ldap_display_name}))",
            attributes=["schemaIDGUID"],
        )
        if (
            not self.conn.entries
            or "schemaIDGUID" not in self.conn.entries[0]
            or not self.conn.entries[0]["schemaIDGUID"].raw_values
        ):
            return None
        return decode_schema_guid(self.conn.entries[0]["schemaIDGUID"].raw_values[0])

    def _resolve_attr(self, ldap_display_name: str) -> str | None:
        self.conn.search(
            search_base=self.schema_nc,
            search_filter=f"(&(objectClass=attributeSchema)(ldapDisplayName={ldap_display_name}))",
            attributes=["schemaIDGUID"],
        )
        if not self.conn.entries:
            return None
        entry = self.conn.entries[0]
        raw_guid = None
        if "schemaIDGUID" in entry and entry["schemaIDGUID"].raw_values:
            raw_guid = entry["schemaIDGUID"].raw_values[0]
        return decode_schema_guid(raw_guid) if raw_guid else None
