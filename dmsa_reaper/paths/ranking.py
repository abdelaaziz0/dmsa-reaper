from __future__ import annotations

from dmsa_reaper.models import PathCandidate


PRIORITY = {
    "postpatch-mutual-pair":     0,
    "existing-dmsa-postpatch-mutual": 1,
    "existing-dmsa-legacy-link": 2,
    "legacy-oneway-link":        3,
    "self-write-map":            4,
    "self-pkinit-loop":          5,
    # Indirect paths require an extra DACL-modification step before the main
    # primitive can run; ranked last since they are higher-effort and lower-confidence.
    "dacl-container-escalate":   6,
    "dacl-target-escalate":      7,
}


def rank_paths(paths: list[PathCandidate]) -> list[PathCandidate]:
    return sorted(paths, key=lambda p: (PRIORITY.get(p.primitive, 99), p.id))
