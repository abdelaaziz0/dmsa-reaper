from __future__ import annotations

from typing import Any

from dmsa_reaper.models import MapState, PathCandidate
from dmsa_reaper.ops.framework import assess_ouroboros


def export_graph(state: MapState, paths: list[PathCandidate], output_format: str) -> dict[str, Any] | str:
    if output_format == "markdown":
        return graph_markdown(state, paths)
    if output_format not in {"bloodhound-legacy", "json"}:
        raise ValueError("--format must be 'bloodhound-legacy', 'json', or 'markdown'")
    edges = []
    for path in paths:
        base = {
            "principal_sid": path.principal,
            "target_dn": path.target_dn,
            "container_dn": path.container_dn,
            "dmsa_dn": path.dmsa_dn,
            "primitive": path.primitive,
            "path_id": path.id,
            "required_rights": path.required_rights,
            "confidence": path.confidence.value if hasattr(path.confidence, "value") else str(path.confidence),
            "executable": path.executable,
            "warnings": path.environment_warnings,
            "verification_state": {
                "ldap": "not-run",
                "kerberos_dmsa": "not-run",
            },
        }
        if path.container_dn:
            edges.append({"edge_type": "CanCreateDMSA", **base})
        if path.target_dn:
            edges.append({"edge_type": "CanLinkDMSAToTarget", **base})
        if path.primitive in {
            "postpatch-mutual-pair",
            "existing-dmsa-postpatch-mutual",
            "legacy-oneway-link",
            "existing-dmsa-legacy-link",
            "dacl-container-escalate",
            "dacl-target-escalate",
        }:
            edges.append({"edge_type": "BadSuccessorPath", **base})
        if path.primitive in {"postpatch-mutual-pair", "existing-dmsa-postpatch-mutual", "self-pkinit-loop"}:
            edges.append({"edge_type": "OuroborosCandidate", **base})
    return {
        "schema": "dmsa-reaper-graph/v1",
        "format": "bloodhound-legacy-standalone" if output_format == "bloodhound-legacy" else "json",
        "domain": state.environment.domain,
        "principal_sid": state.current_principal.sid if state.current_principal else None,
        "edges": edges,
        "notes": [
            "This is a standalone non-secret graph export.",
            "BloodHound custom-edge import support depends on the deployed BloodHound version.",
        ],
        "secrets_logged": False,
    }


def graph_markdown(state: MapState, paths: list[PathCandidate]) -> str:
    assessment = assess_ouroboros(state)
    lines = [
        "# dMSA-Reaper Graph Export",
        "",
        f"- Domain: `{state.environment.domain}`",
        f"- Principal SID: `{state.current_principal.sid if state.current_principal else None}`",
        f"- Path count: `{len(paths)}`",
        f"- Ouroboros status: `{assessment['ouroboros_status']}`",
        "",
        "| Path | Primitive | Executable | Target | Container |",
        "| --- | --- | --- | --- | --- |",
    ]
    for path in paths:
        lines.append(
            f"| `{path.id}` | `{path.primitive}` | `{str(path.executable).lower()}` | "
            f"`{path.target_dn or ''}` | `{path.container_dn or ''}` |"
        )
    lines.extend([
        "",
        "No passwords, keys, tickets, hashes, or session material are included.",
    ])
    return "\n".join(lines) + "\n"
