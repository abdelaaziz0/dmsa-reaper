from __future__ import annotations

from typing import Any

from dmsa_reaper.models import MapState, PathCandidate
from dmsa_reaper.paths.classifier import classify_paths


def classify_ouroboros_paths(state: MapState) -> list[PathCandidate]:
    """Return patched-DC paths that can be extended into Ouroboros.

    Creating the dMSA makes the creator its owner.  The owner can use implicit
    WriteDACL to grant itself GenericAll on that newly created object, so the
    externally delegated prerequisites are the same bidirectional migration
    rights as the postpatch mutual-pair path.
    """
    paths: list[PathCandidate] = []
    for base in classify_paths(state, expand_targets=True):
        if base.primitive != "postpatch-mutual-pair":
            continue
        paths.append(
            base.model_copy(
                update={
                    "id": f"OURO-{base.id.removeprefix('BS-')}",
                    "primitive": "ouroboros",
                    "required_rights": [
                        *base.required_rights,
                        "Owner-implied WriteDACL on the newly created dMSA",
                    ],
                }
            )
        )
    return paths


def active_ouroboros_findings(state: MapState) -> list[dict[str, Any]]:
    """Describe existing dMSAs with one or both Ouroboros persistence markers."""
    findings: list[dict[str, Any]] = []
    for dmsa in state.dmsas:
        has_shadow_credential = dmsa.key_credential_count > 0
        is_self_authorized = dmsa.ouroboros_self_authorized
        if not has_shadow_credential and not is_self_authorized:
            continue
        findings.append(
            {
                "dn": dmsa.dn,
                "sam": dmsa.sam,
                "sid": dmsa.sid,
                "target_dn": dmsa.preceded_by,
                "key_credential_count": dmsa.key_credential_count,
                "self_authorized": is_self_authorized,
                "status": (
                    "active-ouroboros"
                    if has_shadow_credential and is_self_authorized
                    else "partial-indicator"
                ),
            }
        )
    return findings

