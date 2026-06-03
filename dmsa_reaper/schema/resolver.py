from __future__ import annotations

from ldap3 import Connection

from dmsa_reaper.constants import DMSA_CLASS, DMSA_RELEVANT_ATTRS, FALLBACK_GUIDS
from dmsa_reaper.models import SchemaCache
from dmsa_reaper.schema.guids import decode_schema_guid
from dmsa_reaper.schema.searchflags import is_confidential


class SchemaResolver:
    def __init__(self, conn: Connection, schema_nc: str, config_nc: str | None = None):
        self.conn = conn
        self.schema_nc = schema_nc
        self.config_nc = config_nc

    def resolve(self) -> SchemaCache:
        cache = SchemaCache(schema_nc=self.schema_nc, config_nc=self.config_nc)
        cache.object_version = self._read_schema_object_version()
        dmsa_guid = self._resolve_class_guid(DMSA_CLASS)
        if dmsa_guid:
            cache.dmsa_class_guid = dmsa_guid
            cache.dmsa_class_guid_source = "schema_query"
        elif DMSA_CLASS in FALLBACK_GUIDS:
            cache.dmsa_class_guid = FALLBACK_GUIDS[DMSA_CLASS]
            cache.dmsa_class_guid_source = "fallback"

        for attr in DMSA_RELEVANT_ATTRS:
            guid, flags = self._resolve_attr(attr)
            if guid:
                cache.attr_guids[attr] = guid
                cache.attr_guid_sources[attr] = "schema_query"
            elif attr in FALLBACK_GUIDS:
                cache.attr_guids[attr] = FALLBACK_GUIDS[attr]
                cache.attr_guid_sources[attr] = "fallback"
            if flags is not None:
                cache.search_flags[attr] = flags
                if is_confidential(flags):
                    cache.confidential_attrs.append(attr)

        return cache

    def _read_schema_object_version(self) -> int | None:
        self.conn.search(
            search_base=self.schema_nc,
            search_filter="(objectClass=dMD)",
            attributes=["objectVersion"],
        )
        if not self.conn.entries:
            return None
        value = self.conn.entries[0]["objectVersion"].value
        return int(value) if value is not None else None

    def _resolve_class_guid(self, ldap_display_name: str) -> str | None:
        self.conn.search(
            search_base=self.schema_nc,
            search_filter=f"(&(objectClass=classSchema)(ldapDisplayName={ldap_display_name}))",
            attributes=["schemaIDGUID"],
        )
        if not self.conn.entries:
            return None
        return decode_schema_guid(self.conn.entries[0]["schemaIDGUID"].raw_values[0])

    def _resolve_attr(self, ldap_display_name: str) -> tuple[str | None, int | None]:
        self.conn.search(
            search_base=self.schema_nc,
            search_filter=f"(&(objectClass=attributeSchema)(ldapDisplayName={ldap_display_name}))",
            attributes=["schemaIDGUID", "searchFlags"],
        )
        if not self.conn.entries:
            return None, None
        entry = self.conn.entries[0]
        raw_guid = None
        if "schemaIDGUID" in entry and entry["schemaIDGUID"].raw_values:
            raw_guid = entry["schemaIDGUID"].raw_values[0]
        guid = decode_schema_guid(raw_guid) if raw_guid else None
        flags = int(entry["searchFlags"].value or 0) if "searchFlags" in entry else 0
        return guid, flags
