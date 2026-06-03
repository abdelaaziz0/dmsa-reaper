from __future__ import annotations

import base64
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class CheckStatus(str, Enum):
    present = "present"
    absent = "absent"
    unknown = "unknown"
    unreadable = "unreadable"
    error = "error"


def _status_from_bool(value: Any) -> CheckStatus:
    return CheckStatus.present if bool(value) else CheckStatus.absent


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class Environment(BaseModel):
    domain: str | None = None
    forest: str | None = None
    default_nc: str | None = None
    config_nc: str | None = None
    schema_nc: str | None = None
    dmsa_schema_status: CheckStatus = CheckStatus.unknown
    server_2025_dc_status: CheckStatus = CheckStatus.unknown
    kds_root_key_status: CheckStatus = CheckStatus.unknown
    dmsa_capable_status: CheckStatus = CheckStatus.unknown
    ldap_signing_status: CheckStatus = CheckStatus.unknown
    ldaps_status: CheckStatus = CheckStatus.unknown
    channel_binding_status: CheckStatus = CheckStatus.unknown
    # Compatibility booleans kept for older fixtures and path classifiers. New
    # map output should prefer the status fields above.
    has_dmsa_schema: bool = False
    has_server_2025_dc: bool = False
    has_kds_root_key: bool = False
    dmsa_capable: bool = False
    dcs: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _sync_status_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        pairs = (
            ("has_dmsa_schema", "dmsa_schema_status"),
            ("has_server_2025_dc", "server_2025_dc_status"),
            ("has_kds_root_key", "kds_root_key_status"),
            ("dmsa_capable", "dmsa_capable_status"),
        )
        for bool_field, status_field in pairs:
            if status_field not in data and bool_field in data:
                data[status_field] = _status_from_bool(data[bool_field]).value
            if bool_field not in data and status_field in data:
                data[bool_field] = data[status_field] == CheckStatus.present.value
        return data


class SchemaCache(BaseModel):
    schema_nc: str | None = None
    config_nc: str | None = None
    object_version: int | None = None
    dmsa_class_guid: str | None = None
    dmsa_class_guid_source: str | None = None
    attr_guids: dict[str, str] = Field(default_factory=dict)
    attr_guid_sources: dict[str, str] = Field(default_factory=dict)
    search_flags: dict[str, int] = Field(default_factory=dict)
    confidential_attrs: list[str] = Field(default_factory=list)


class Principal(BaseModel):
    name: str | None = None
    sid: str
    groups: list[str] = Field(default_factory=list)


class Right(BaseModel):
    principal_sid: str
    right: str
    object_dn: str
    attribute: str | None = None
    object_type_guid: str | None = None
    inherited: bool = False
    source: str | None = None


class DmsaObject(BaseModel):
    dn: str
    sam: str | None = None
    sid: str | None = None
    state: int | None = None
    group_msa_membership_raw_b64: str | None = None
    preceded_by: str | None = None
    superseded_link: str | None = None
    key_credential_link_present: bool = False
    owner_sid: str | None = None
    # rights: what the current operator can do TO this dMSA.
    rights: list[Right] = Field(default_factory=list)
    # self_rights: what the dMSA principal can do TO ITSELF (evaluated with
    # principal_sids={dmsa.sid} and is_self=True). Used for self-write-map
    # and self-pkinit-loop classification.
    self_rights: list[Right] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


class ContainerObject(BaseModel):
    dn: str
    object_class: str | None = None
    owner_sid: str | None = None
    rights: list[Right] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


class TargetObject(BaseModel):
    dn: str
    sam: str | None = None
    sid: str | None = None
    object_classes: list[str] = Field(default_factory=list)
    owner_sid: str | None = None
    writable_attrs: list[str] = Field(default_factory=list)
    rights: list[Right] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    primitive: str
    principal: str
    object_dn: str
    rights: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.medium


class PathCandidate(BaseModel):
    id: str
    primitive: str
    principal: str
    dmsa_dn: str | None = None
    container_dn: str | None = None
    target_dn: str | None = None
    required_rights: list[str] = Field(default_factory=list)
    requires_create_dmsa: bool = False
    requires_modify_dmsa: bool = False
    requires_modify_target: bool = False
    # Indirect DACL-escalation paths: operator must first modify the DACL of the
    # container or target before the main primitive can run.
    requires_modify_container_dacl: bool = False
    requires_modify_target_dacl: bool = False
    # executable=False: path is emitted for awareness but cannot be run directly.
    # The exploit command will reject non-executable paths with a clear message.
    executable: bool = True
    # requires_operator_target=True: primitive needs --target-dn at exploit time.
    requires_operator_target: bool = False
    # candidate_targets_count > 0: grouped path covers this many viable targets.
    # Use --expand-targets on the paths command to see one row per target.
    candidate_targets_count: int = 0
    verification_modes: list[str] = Field(default_factory=lambda: ["ldap"])
    rollback_available: bool = True
    confidence: Confidence = Confidence.medium
    # Non-empty when environment prerequisites are uncertain (e.g. KDS unknown).
    # Exploitation may fail until all environment checks are resolved.
    environment_warnings: list[str] = Field(default_factory=list)


class MapState(BaseModel):
    environment: Environment
    schema_cache: SchemaCache
    current_principal: Principal | None = None
    dmsas: list[DmsaObject] = Field(default_factory=list)
    dmsa_read_warnings: list[str] = Field(default_factory=list)
    unreadable_dmsa_candidates: list[str] = Field(default_factory=list)
    dmsa_enumeration_status: CheckStatus = CheckStatus.unknown
    containers: list[ContainerObject] = Field(default_factory=list)
    targets: list[TargetObject] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    ouroboros_capable: bool = False
    ouroboros_status: str = "unknown"
    ouroboros_blockers: list[str] = Field(default_factory=list)
    ouroboros_warnings: list[str] = Field(default_factory=list)
    ouroboros_required_proofs: list[str] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "MapState":
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.model_dump_json(indent=2), encoding="utf-8")


class AttributeValue(BaseModel):
    type: Literal["bytes", "str", "int", "float", "bool", "none", "dn", "sid", "security_descriptor"]
    value: str | int | float | bool | None = None

    @classmethod
    def from_python(cls, value: Any) -> "AttributeValue":
        if isinstance(value, cls):
            return value
        if isinstance(value, bytes):
            return cls(type="bytes", value=base64.b64encode(value).decode("ascii"))
        if isinstance(value, bytearray):
            return cls(type="bytes", value=base64.b64encode(bytes(value)).decode("ascii"))
        if isinstance(value, bool):
            return cls(type="bool", value=value)
        if isinstance(value, int):
            return cls(type="int", value=value)
        if isinstance(value, float):
            return cls(type="float", value=value)
        if value is None:
            return cls(type="none", value=None)
        return cls(type="str", value=str(value))

    @classmethod
    def security_descriptor(cls, raw_bytes: bytes) -> "AttributeValue":
        """Wrap a raw nTSecurityDescriptor as a typed, base64-encoded value."""
        return cls(type="security_descriptor", value=base64.b64encode(raw_bytes).decode("ascii"))

    def to_python(self) -> Any:
        if self.type in ("bytes", "security_descriptor"):
            return base64.b64decode(str(self.value or ""))
        return self.value

    def comparison_key(self) -> tuple[str, str]:
        # Normalize semantic binary types (security_descriptor, dn, sid) to "bytes" so that
        # rollback verification compares correctly against raw LDAP values parsed as "bytes".
        normalized = (
            "bytes" if self.type in ("bytes", "security_descriptor", "dn", "sid") else self.type
        )
        return (normalized, "" if self.value is None else str(self.value))


class AttributeChange(BaseModel):
    dn: str
    attribute: str
    before: list[AttributeValue] | None = None
    after: list[AttributeValue] | None = None
    mode: Literal["add", "replace", "delete"]
    step_name: str | None = None
    step_status: Literal["planned", "written", "verified", "rolled-back"] | None = None

    @field_validator("before", "after", mode="before")
    @classmethod
    def _coerce_values(cls, values):
        if values is None:
            return None
        if not isinstance(values, list | tuple):
            values = [values]
        coerced = []
        for value in values:
            if isinstance(value, AttributeValue):
                coerced.append(value)
            elif isinstance(value, dict) and {"type", "value"} <= set(value):
                coerced.append(value)
            else:
                coerced.append(AttributeValue.from_python(value))
        return coerced

    def before_python(self) -> list[Any] | None:
        if self.before is None:
            return None
        return [value.to_python() for value in self.before]

    def after_python(self) -> list[Any] | None:
        if self.after is None:
            return None
        return [value.to_python() for value in self.after]


class Operation(BaseModel):
    id: str
    primitive: str
    path_id: str | None = None
    status: str = "planned"
    created_dns: list[str] = Field(default_factory=list)
    maybe_created_dns: list[str] = Field(default_factory=list)
    changed_attrs: list[AttributeChange] = Field(default_factory=list)
    requested_ticket: bool = False
    # "verified" means the operation's current active LDAP/external state is
    # verified. It is cleared after rollback because the exploit state is gone.
    verified: bool = False
    # Historical verification flags remain true after rollback to preserve proof
    # that a verification succeeded before the operation was reverted.
    verified_ldap: bool = False
    verified_external: bool = False
    rollback_available: bool = True
    rolled_back: bool = False
    rollback_verified: bool = False
    tool_version: str | None = None
    started_at: str = Field(default_factory=_utc_now_iso)
    updated_at: str = Field(default_factory=_utc_now_iso)
    ldap_verified_at: str | None = None
    external_verified_at: str | None = None
    rolled_back_at: str | None = None
    rollback_verified_at: str | None = None
    scope_file_hash: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    recovery_notes: list[str] = Field(default_factory=list)
    manual_rollback_commands: list[str] = Field(default_factory=list)
