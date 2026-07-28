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


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class Environment(BaseModel):
    domain: str | None = None
    default_nc: str | None = None
    config_nc: str | None = None
    schema_nc: str | None = None
    dmsa_schema_status: CheckStatus = CheckStatus.unknown
    server_2025_dc_status: CheckStatus = CheckStatus.unknown
    kds_root_key_status: CheckStatus = CheckStatus.unknown
    dmsa_capable_status: CheckStatus = CheckStatus.unknown
    mapped_dc_host: str | None = None
    mapped_dc_ip: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _load_legacy_statuses(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        legacy = (
            ("has_dmsa_schema", "dmsa_schema_status"),
            ("has_server_2025_dc", "server_2025_dc_status"),
            ("has_kds_root_key", "kds_root_key_status"),
            ("dmsa_capable", "dmsa_capable_status"),
        )
        for old_name, status_name in legacy:
            if status_name not in data and old_name in data:
                data[status_name] = (
                    CheckStatus.present.value
                    if data[old_name]
                    else CheckStatus.absent.value
                )
        return data


class SchemaCache(BaseModel):
    dmsa_class_guid: str | None = None
    dmsa_class_guid_resolved: bool = False
    attr_guids: dict[str, str] = Field(default_factory=dict)


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
    object_guid: str | None = None
    sam: str | None = None
    sid: str | None = None
    state: int | None = None
    preceded_by: str | None = None
    superseded_link: str | None = None
    owner_sid: str | None = None
    rights: list[Right] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


class ContainerObject(BaseModel):
    dn: str
    object_guid: str | None = None
    object_class: str | None = None
    owner_sid: str | None = None
    rights: list[Right] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


class TargetObject(BaseModel):
    dn: str
    object_guid: str | None = None
    sam: str | None = None
    sid: str | None = None
    object_classes: list[str] = Field(default_factory=list)
    owner_sid: str | None = None
    writable_attrs: list[str] = Field(default_factory=list)
    rights: list[Right] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


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
    candidate_targets_count: int = 0
    confidence: Confidence = Confidence.medium
    # Non-empty when environment prerequisites are uncertain (e.g. KDS unknown).
    # Exploitation may fail until all environment checks are resolved.
    environment_warnings: list[str] = Field(default_factory=list)


class MapState(BaseModel):
    environment: Environment
    schema_cache: SchemaCache
    current_principal: Principal | None = None
    dmsas: list[DmsaObject] = Field(default_factory=list)
    containers: list[ContainerObject] = Field(default_factory=list)
    targets: list[TargetObject] = Field(default_factory=list)

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
        # Normalize semantic binary types for comparisons against raw LDAP values
        # parsed as "bytes".
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
    step_status: Literal["planned", "written", "verified", "cleaned"] | None = None

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
    cleanup_available: bool = True
    cleaned_up: bool = False
    cleanup_verified: bool = False
    tool_version: str | None = None
    started_at: str = Field(default_factory=_utc_now_iso)
    updated_at: str = Field(default_factory=_utc_now_iso)
    cleaned_up_at: str | None = None
    cleanup_verified_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    recovery_notes: list[str] = Field(default_factory=list)
