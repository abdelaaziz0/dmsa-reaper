from __future__ import annotations

import hashlib
import json

from dmsa_reaper.models import CheckStatus, Confidence, MapState, PathCandidate

# Rights that are interesting on a dMSA object for informational self-write
# mapping. These are not all sufficient for the existing-dMSA migration-link
# primitives below.
_DANGEROUS_DMSA_RIGHTS = frozenset({
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "WriteProperty:msDS-KeyCredentialLink",
    "WriteProperty:msDS-GroupMSAMembership",
    "WriteProperty:msDS-ManagedAccountPrecededByLink",
    "WriteProperty:msDS-DelegatedMSAState",
})

_DMSA_MIGRATION_ATTR_RIGHTS = frozenset({
    "WriteProperty:msDS-ManagedAccountPrecededByLink",
    "WriteProperty:msDS-DelegatedMSAState",
})

# Rights that allow creating a dMSA child in a container.
# GenericWrite does NOT imply CreateChild in the AD DS generic-rights mapping.
_CREATE_DMSA_RIGHTS = frozenset({"CreateChild:dMSA", "CreateChild", "GenericAll"})

# Rights that let the operator modify a container or target DACL, enabling
# them to grant themselves the rights they lack (indirect escalation).
# Direct DACL replacement requires WRITE_DAC.  WriteOwner is not sufficient
# unless execution also performs and later restores an ownership transition,
# which these primitives deliberately do not do.
_DACL_CONTROL_RIGHTS = frozenset({"WriteDACL", "GenericAll"})

# Self-write surfaces used for self-pkinit-loop detection (evaluated on self_rights).
_SELF_KEY_CRED_RIGHTS = frozenset({
    "GenericAll", "WriteProperty:msDS-KeyCredentialLink",
})
_SELF_GMSA_RIGHTS = frozenset({
    "GenericAll", "WriteProperty:msDS-GroupMSAMembership",
})

# Self-write surfaces that make self-write-map relevant.
_SELF_WRITE_SURFACE = _DANGEROUS_DMSA_RIGHTS

# Target attributes required on the target object for the postpatch path.
_POSTPATCH_TARGET_ATTRS = frozenset({
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededServiceAccountState",
})

# Well-known relative identifiers (RIDs) for accounts that must not be silently
# included in legacy-oneway-link paths by default — these accounts have
# domain-wide Kerberos impact if their PAC is inherited.
_SENSITIVE_RIDS = frozenset({500, 501, 502})  # Administrator, Guest, krbtgt


def _principal_from_rights(rights_list) -> str:
    return rights_list[0].principal_sid if rights_list else "unknown"


def _has_dmsa_migration_write(right_names: set[str]) -> bool:
    return (
        "GenericAll" in right_names
        or "GenericWrite" in right_names
        or _DMSA_MIGRATION_ATTR_RIGHTS.issubset(right_names)
    )


def _dmsa_migration_rights(right_names: set[str]) -> set[str]:
    if "GenericAll" in right_names:
        return {"GenericAll"}
    if "GenericWrite" in right_names:
        return {"GenericWrite"}
    return set(right_names & _DMSA_MIGRATION_ATTR_RIGHTS)


def _rid_from_sid(sid: str) -> int | None:
    """Return the RID (last integer component) from an SDDL SID string."""
    try:
        return int(sid.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return None


def _is_sensitive_legacy_target(target, current_principal_sid: str | None) -> bool:
    """Return True when a target should be excluded from legacy-oneway-link by default.

    Filters accounts whose PAC inheritance would be especially impactful:
      - Well-known built-in accounts (Administrator, Guest, krbtgt) by RID.
      - The current operator's own account (to avoid self-targeting).
      - Domain controller objects (identified by standard DC OU placement).

    Operators can expand the target set with --target-filter at map time, or
    use --expand-targets to see what targets remain after filtering.
    """
    if target.sid:
        rid = _rid_from_sid(target.sid)
        if rid is not None and rid in _SENSITIVE_RIDS:
            return True
        if current_principal_sid and target.sid == current_principal_sid:
            return True
    # Filter DC objects by their standard OU placement.  This covers the common
    # case without needing primaryGroupID (which is not stored in TargetObject).
    if target.dn and ",ou=domain controllers," in target.dn.lower():
        return True
    return False


def _env_warnings_for_status(env) -> list[str]:
    """Build environment warning strings when dMSA capability is not fully confirmed."""
    warnings: list[str] = []
    if env.dmsa_capable_status != CheckStatus.present:
        kds = env.kds_root_key_status.value
        capable = env.dmsa_capable_status.value
        warnings.append(
            f"dmsa_capable_status={capable}; kds_root_key_status={kds}. "
            "Environment prerequisites not fully confirmed — "
            "live exploitation may fail until KDS root key presence is verified. "
            "Use 'dmsa-reaper map' against the DC to refresh."
        )
    return warnings


def classify_paths(state: MapState, *, expand_targets: bool = False) -> list[PathCandidate]:
    """Classify executable dMSA paths from map state.

    By default, paths that can target any of several accounts are emitted once
    per viable container with candidate_targets_count set.  Pass expand_targets=True
    to emit one path per (container, target) pair instead (verbose mode).

    Paths are emitted when dMSA capability is *confirmed present* (full
    confidence) or *uncertain* (KDS unknown — lower confidence, environment
    warnings attached).  Paths are suppressed only when capability is confirmed
    absent.
    """
    paths: list[PathCandidate] = []
    idx = 1

    dmsa_capable = state.environment.dmsa_capable_status == CheckStatus.present
    dmsa_maybe = state.environment.dmsa_capable_status == CheckStatus.unknown

    # Determine confidence and environment warnings based on capability status.
    if dmsa_capable:
        _base_confidence = Confidence.high
        _env_warn: list[str] = []
    elif dmsa_maybe:
        # ACL evidence exists but environment is not fully confirmed.
        # Emit paths at lower confidence so operators can see what rights exist,
        # but know that live exploitation requires KDS confirmation first.
        _base_confidence = Confidence.low
        _env_warn = _env_warnings_for_status(state.environment)
    else:
        # Capability confirmed absent — suppress all dMSA paths.
        _base_confidence = Confidence.low
        _env_warn = []

    # Whether to emit any paths that require dMSA capability.
    emit = dmsa_capable or dmsa_maybe

    # Current principal SID used to filter self-targeting in legacy paths.
    _op_sid = state.current_principal.sid if state.current_principal else None

    # ------------------------------------------------------------------ #
    # 1. postpatch-mutual-pair  (main 2026 path)                          #
    #    Requires: CreateChild:dMSA on container + both target-side attrs  #
    # ------------------------------------------------------------------ #
    if emit:
        for container in state.containers:
            right_names = {r.right for r in container.rights}
            if not right_names & _CREATE_DMSA_RIGHTS:
                continue
            viable_targets = [
                t for t in state.targets
                if _POSTPATCH_TARGET_ATTRS.issubset(set(t.writable_attrs))
            ]
            if not viable_targets:
                continue
            if expand_targets:
                for target in viable_targets:
                    paths.append(PathCandidate(
                        id=f"P-{idx:04d}",
                        primitive="postpatch-mutual-pair",
                        principal=_principal_from_rights(container.rights),
                        container_dn=container.dn,
                        target_dn=target.dn,
                        required_rights=[
                            "CreateChild:msDS-DelegatedManagedServiceAccount on container",
                            "WriteProperty:msDS-SupersededManagedAccountLink on target",
                            "WriteProperty:msDS-SupersededServiceAccountState on target",
                        ],
                        requires_create_dmsa=True,
                        requires_modify_dmsa=True,
                        requires_modify_target=True,
                        confidence=_base_confidence,
                        environment_warnings=_env_warn,
                    ))
                    idx += 1
            else:
                paths.append(PathCandidate(
                    id=f"P-{idx:04d}",
                    primitive="postpatch-mutual-pair",
                    principal=_principal_from_rights(container.rights),
                    container_dn=container.dn,
                    required_rights=[
                        "CreateChild:msDS-DelegatedManagedServiceAccount on container",
                        "WriteProperty:msDS-SupersededManagedAccountLink on target",
                        "WriteProperty:msDS-SupersededServiceAccountState on target",
                    ],
                    requires_create_dmsa=True,
                    requires_modify_dmsa=True,
                    requires_modify_target=True,
                    requires_operator_target=True,
                    candidate_targets_count=len(viable_targets),
                    confidence=_base_confidence,
                    environment_warnings=_env_warn,
                ))
                idx += 1

    # ------------------------------------------------------------------ #
    # 2. existing-dmsa-postpatch-mutual                                    #
    #    Requires: exact dMSA migration writes plus target-side attrs      #
    # ------------------------------------------------------------------ #
    for dmsa in state.dmsas:
        right_names = {r.right for r in dmsa.rights}
        if not _has_dmsa_migration_write(right_names):
            continue
        migration_rights = _dmsa_migration_rights(right_names)
        viable_targets = [
            t for t in state.targets
            if _POSTPATCH_TARGET_ATTRS.issubset(set(t.writable_attrs))
        ]
        if viable_targets:
            if expand_targets:
                for target in viable_targets:
                    paths.append(PathCandidate(
                        id=f"P-{idx:04d}",
                        primitive="existing-dmsa-postpatch-mutual",
                        principal=_principal_from_rights(dmsa.rights),
                        dmsa_dn=dmsa.dn,
                        target_dn=target.dn,
                        required_rights=sorted(
                            migration_rights
                            | {
                                "WriteProperty:msDS-SupersededManagedAccountLink on target",
                                "WriteProperty:msDS-SupersededServiceAccountState on target",
                            }
                        ),
                        requires_modify_dmsa=True,
                        requires_modify_target=True,
                        confidence=Confidence.high,
                    ))
                    idx += 1
            else:
                paths.append(PathCandidate(
                    id=f"P-{idx:04d}",
                    primitive="existing-dmsa-postpatch-mutual",
                    principal=_principal_from_rights(dmsa.rights),
                    dmsa_dn=dmsa.dn,
                    required_rights=sorted(
                        migration_rights
                        | {
                            "WriteProperty:msDS-SupersededManagedAccountLink on target",
                            "WriteProperty:msDS-SupersededServiceAccountState on target",
                        }
                    ),
                    requires_modify_dmsa=True,
                    requires_modify_target=True,
                    requires_operator_target=True,
                    candidate_targets_count=len(viable_targets),
                    confidence=Confidence.high,
                ))
                idx += 1

        paths.append(PathCandidate(
            id=f"P-{idx:04d}",
            primitive="existing-dmsa-legacy-link",
            principal=_principal_from_rights(dmsa.rights),
            dmsa_dn=dmsa.dn,
            required_rights=sorted(migration_rights),
            requires_modify_dmsa=True,
            requires_operator_target=True,
            confidence=Confidence.medium,
            verification_modes=["ldap"],
        ))
        idx += 1

    # ------------------------------------------------------------------ #
    # 3. legacy-oneway-link  (unpatched / pre-CVE-2025-53779 / lab/CTF)   #
    #    Requires: CreateChild:dMSA on container; no target-side write     #
    # ------------------------------------------------------------------ #
    if emit:
        for container in state.containers:
            right_names = {r.right for r in container.rights}
            if not right_names & _CREATE_DMSA_RIGHTS:
                continue

            # Exclude sensitive built-in accounts from legacy paths by default.
            # These accounts (Administrator, krbtgt, Guest, operator itself)
            # have domain-wide Kerberos impact and must not appear in default output.
            safe_targets = [
                t for t in state.targets
                if not _is_sensitive_legacy_target(t, _op_sid)
            ]

            if expand_targets:
                for target in safe_targets:
                    paths.append(PathCandidate(
                        id=f"P-{idx:04d}",
                        primitive="legacy-oneway-link",
                        principal=_principal_from_rights(container.rights),
                        container_dn=container.dn,
                        target_dn=target.dn,
                        required_rights=[
                            "CreateChild:msDS-DelegatedManagedServiceAccount on container",
                            "WriteProperty:msDS-ManagedAccountPrecededByLink on dMSA",
                        ],
                        requires_create_dmsa=True,
                        requires_modify_dmsa=True,
                        requires_modify_target=False,
                        confidence=Confidence.medium,
                        environment_warnings=_env_warn,
                        verification_modes=["ldap"],
                    ))
                    idx += 1
            else:
                if safe_targets:
                    paths.append(PathCandidate(
                        id=f"P-{idx:04d}",
                        primitive="legacy-oneway-link",
                        principal=_principal_from_rights(container.rights),
                        container_dn=container.dn,
                        required_rights=[
                            "CreateChild:msDS-DelegatedManagedServiceAccount on container",
                            "WriteProperty:msDS-ManagedAccountPrecededByLink on dMSA",
                        ],
                        requires_create_dmsa=True,
                        requires_modify_dmsa=True,
                        requires_modify_target=False,
                        requires_operator_target=True,
                        candidate_targets_count=len(safe_targets),
                        confidence=Confidence.medium,
                        environment_warnings=_env_warn,
                        verification_modes=["ldap"],
                    ))
                    idx += 1

    # ------------------------------------------------------------------ #
    # 4. self-write-map                                                    #
    #    After dMSA control: what can the dMSA write to itself?           #
    #    Evaluated on self_rights (dmsa.sid acting as itself, is_self=True) #
    # ------------------------------------------------------------------ #
    for dmsa in state.dmsas:
        self_right_names = {r.right for r in dmsa.self_rights}
        if not self_right_names & _SELF_WRITE_SURFACE:
            continue
        paths.append(PathCandidate(
            id=f"P-{idx:04d}",
            primitive="self-write-map",
            principal=dmsa.sid or "unknown",
            dmsa_dn=dmsa.dn,
            required_rights=sorted(self_right_names & _SELF_WRITE_SURFACE),
            requires_modify_dmsa=True,
            executable=False,
            confidence=Confidence.medium,
        ))
        idx += 1

    # ------------------------------------------------------------------ #
    # 5. self-pkinit-loop  (candidate — Ouroboros technique)              #
    #    Requires: dMSA can write msDS-KeyCredentialLink AND               #
    #              msDS-GroupMSAMembership on itself (via self_rights)     #
    # ------------------------------------------------------------------ #
    for dmsa in state.dmsas:
        self_right_names = {r.right for r in dmsa.self_rights}
        has_key_cred = bool(self_right_names & _SELF_KEY_CRED_RIGHTS)
        has_gmsa = bool(self_right_names & _SELF_GMSA_RIGHTS)
        if not (has_key_cred and has_gmsa):
            continue
        paths.append(PathCandidate(
            id=f"P-{idx:04d}",
            primitive="self-pkinit-loop",
            principal=dmsa.sid or "unknown",
            dmsa_dn=dmsa.dn,
            required_rights=[
                "WriteProperty:msDS-KeyCredentialLink (self)",
                "WriteProperty:msDS-GroupMSAMembership (self)",
            ],
            requires_modify_dmsa=True,
            executable=False,
            confidence=Confidence.medium,
        ))
        idx += 1

    # ------------------------------------------------------------------ #
    # 6. dacl-container-escalate                                          #
    #    Operator has WriteDACL on a container but lacks                   #
    #    CreateChild:dMSA.  They can modify the container DACL first,      #
    #    then follow the postpatch or legacy path.                         #
    # ------------------------------------------------------------------ #
    if emit:
        for container in state.containers:
            right_names = {r.right for r in container.rights}
            has_dacl_ctrl = bool(right_names & _DACL_CONTROL_RIGHTS)
            has_create = bool(right_names & _CREATE_DMSA_RIGHTS)
            # Only emit as indirect path when operator can control the DACL but does
            # not already have CreateChild rights (which would give a direct path above).
            if not has_dacl_ctrl or has_create:
                continue
            paths.append(PathCandidate(
                id=f"P-{idx:04d}",
                primitive="dacl-container-escalate",
                principal=_principal_from_rights(container.rights),
                container_dn=container.dn,
                required_rights=sorted(right_names & _DACL_CONTROL_RIGHTS),
                requires_create_dmsa=True,
                requires_modify_dmsa=True,
                requires_modify_container_dacl=True,
                requires_operator_target=True,
                executable=True,
                confidence=Confidence.low,
                environment_warnings=_env_warn,
            ))
            idx += 1

    # ------------------------------------------------------------------ #
    # 7. dacl-target-escalate                                             #
    #    Operator has WriteDACL on a target but lacks the                  #
    #    required target-side WriteProperty attributes.  They can modify   #
    #    the target DACL first, then use the postpatch path.              #
    # ------------------------------------------------------------------ #
    if emit:
        for target in state.targets:
            right_names = {r.right for r in target.rights}
            has_dacl_ctrl = bool(right_names & _DACL_CONTROL_RIGHTS)
            already_has_attrs = _POSTPATCH_TARGET_ATTRS.issubset(set(target.writable_attrs))
            if not has_dacl_ctrl or already_has_attrs:
                continue
            paths.append(PathCandidate(
                id=f"P-{idx:04d}",
                primitive="dacl-target-escalate",
                principal=_principal_from_rights(target.rights),
                target_dn=target.dn,
                required_rights=sorted(right_names & _DACL_CONTROL_RIGHTS),
                requires_modify_target=True,
                requires_modify_target_dacl=True,
                executable=True,
                confidence=Confidence.low,
                environment_warnings=_env_warn,
            ))
            idx += 1

    guid_by_dn: dict[str, str | None] = {}
    guid_by_dn.update({obj.dn.lower(): obj.object_guid for obj in state.containers})
    guid_by_dn.update({obj.dn.lower(): obj.object_guid for obj in state.targets})
    guid_by_dn.update({obj.dn.lower(): obj.object_guid for obj in state.dmsas})
    for path in paths:
        identity = {
            "primitive": path.primitive,
            "principal": path.principal,
            "container_dn": path.container_dn,
            "container_guid": guid_by_dn.get((path.container_dn or "").lower()),
            "dmsa_dn": path.dmsa_dn,
            "dmsa_guid": guid_by_dn.get((path.dmsa_dn or "").lower()),
            "target_dn": path.target_dn,
            "target_guid": guid_by_dn.get((path.target_dn or "").lower()),
            "grouped": path.requires_operator_target,
        }
        digest = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:12]
        path.id = f"BS-{digest}"
    return paths
