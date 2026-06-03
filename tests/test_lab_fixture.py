"""Classifier tests using the dmsalab.local offline fixture.

Validates that the path classifier produces the expected paths — and no
unexpected paths — from the fixture defined in docs/lab-fixture-dmsalab.json.

This serves as a living specification of the lab topology and the expected
dmsa-reaper behavior against it.  The fixture represents a dmsa-reaper map
run as reaper.low against the dmsalab.local ADBuilder lab.

Covered assertions:
  Positive paths (must appear):
    - postpatch-mutual-pair: DMSA-Direct × victim.postpatch (direct operator path)
    - postpatch-mutual-pair: DMSA-Direct × victim.primary (direct × primaryGroupID target)
    - postpatch-mutual-pair: DMSA-PrimaryGroup × victim.postpatch (primaryGroupID × direct target)
    - postpatch-mutual-pair: DMSA-PrimaryGroup × victim.primary (primaryGroupID × primaryGroupID)
    - legacy-oneway-link: from each CreateChild container

  Negative controls (must NOT appear):
    - NO path from OU=DMSA-GenericWriteOnly (GenericWrite ≠ CreateChild)
    - NO dacl-container-escalate for reaper.low (no WriteDACL on any container)
    - NO dacl-target-escalate for reaper.low (no WriteDACL on any target)
    - NO existing-dmsa-* paths (no dMSAs in fixture)
    - NO self-* paths (no dMSAs in fixture)
    - NO postpatch path to victim.legacy (no writable superseded attrs)
    - NO postpatch path to victim.dacl (no writable superseded attrs)
    - NO postpatch path to victim.negative (no writable superseded attrs)
"""
from __future__ import annotations

import pathlib

import pytest

from dmsa_reaper.models import MapState
from dmsa_reaper.paths.classifier import classify_paths
from dmsa_reaper.paths.ranking import rank_paths

_FIXTURE = pathlib.Path(__file__).parent.parent / "docs" / "lab-fixture-dmsalab.json"

_DIRECT_CONTAINER = "OU=DMSA-Direct,OU=Lab,DC=dmsalab,DC=local"
_LEGACY_CONTAINER = "OU=DMSA-Legacy,OU=Lab,DC=dmsalab,DC=local"
_PRIMARYGROUP_CONTAINER = "OU=DMSA-PrimaryGroup,OU=Lab,DC=dmsalab,DC=local"
_GENERICWRITE_CONTAINER = "OU=DMSA-GenericWriteOnly,OU=Lab,DC=dmsalab,DC=local"
_DACL_CONTAINER = "OU=DMSA-DACL-Only,OU=Lab,DC=dmsalab,DC=local"
_NESTED_CONTAINER = "OU=DMSA-Nested,OU=Lab,DC=dmsalab,DC=local"

_VICTIM_POSTPATCH = "CN=victim.postpatch,OU=Targets,OU=Lab,DC=dmsalab,DC=local"
_VICTIM_PRIMARY = "CN=victim.primary,OU=Targets,OU=Lab,DC=dmsalab,DC=local"
_VICTIM_LEGACY = "CN=victim.legacy,OU=Targets,OU=Lab,DC=dmsalab,DC=local"
_VICTIM_DACL = "CN=victim.dacl,OU=Targets,OU=Lab,DC=dmsalab,DC=local"
_VICTIM_NEGATIVE = "CN=victim.negative,OU=NegativeControls,OU=Lab,DC=dmsalab,DC=local"


@pytest.fixture(scope="module")
def lab_state() -> MapState:
    return MapState.model_validate_json(_FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def lab_paths_expanded(lab_state: MapState):
    return rank_paths(classify_paths(lab_state, expand_targets=True))


@pytest.fixture(scope="module")
def lab_paths_grouped(lab_state: MapState):
    return rank_paths(classify_paths(lab_state, expand_targets=False))


# ── fixture sanity ────────────────────────────────────────────────────────────

def test_fixture_file_exists():
    assert _FIXTURE.exists(), f"Fixture file missing: {_FIXTURE}"


def test_fixture_loads_as_mapstate(lab_state):
    assert lab_state.environment.dmsa_capable_status.value == "present"
    assert lab_state.environment.domain == "dmsalab.local"
    assert lab_state.current_principal is not None
    assert lab_state.current_principal.name == "reaper.low"


def test_fixture_environment_is_dmsa_capable(lab_state):
    env = lab_state.environment
    assert env.dmsa_schema_status.value == "present"
    assert env.server_2025_dc_status.value == "present"
    assert env.kds_root_key_status.value == "present"
    assert env.dmsa_capable_status.value == "present"


def test_fixture_container_count(lab_state):
    assert len(lab_state.containers) == 6


def test_fixture_target_count(lab_state):
    assert len(lab_state.targets) == 5


def test_fixture_no_dmsas(lab_state):
    assert lab_state.dmsas == []


# ── positive: postpatch-mutual-pair paths must appear ────────────────────────

def test_postpatch_direct_to_victim_postpatch(lab_paths_expanded):
    """Direct CreateChild container must produce a postpatch path to victim.postpatch."""
    hit = next(
        (p for p in lab_paths_expanded
         if p.primitive == "postpatch-mutual-pair"
         and p.container_dn == _DIRECT_CONTAINER
         and p.target_dn == _VICTIM_POSTPATCH),
        None,
    )
    assert hit is not None, "Expected postpatch-mutual-pair: DMSA-Direct → victim.postpatch"
    assert hit.executable is True


def test_postpatch_direct_to_victim_primary(lab_paths_expanded):
    """Direct container must also produce a postpatch path to the primaryGroupID target."""
    hit = next(
        (p for p in lab_paths_expanded
         if p.primitive == "postpatch-mutual-pair"
         and p.container_dn == _DIRECT_CONTAINER
         and p.target_dn == _VICTIM_PRIMARY),
        None,
    )
    assert hit is not None, "Expected postpatch-mutual-pair: DMSA-Direct → victim.primary"
    assert hit.executable is True


def test_postpatch_primarygroup_to_victim_postpatch(lab_paths_expanded):
    """PrimaryGroupID container (Domain Users CreateChild) must produce a postpatch path."""
    hit = next(
        (p for p in lab_paths_expanded
         if p.primitive == "postpatch-mutual-pair"
         and p.container_dn == _PRIMARYGROUP_CONTAINER
         and p.target_dn == _VICTIM_POSTPATCH),
        None,
    )
    assert hit is not None, "Expected postpatch-mutual-pair: DMSA-PrimaryGroup → victim.postpatch"


def test_postpatch_primarygroup_to_victim_primary(lab_paths_expanded):
    """PrimaryGroupID container × primaryGroupID target must produce a path."""
    hit = next(
        (p for p in lab_paths_expanded
         if p.primitive == "postpatch-mutual-pair"
         and p.container_dn == _PRIMARYGROUP_CONTAINER
         and p.target_dn == _VICTIM_PRIMARY),
        None,
    )
    assert hit is not None, "Expected postpatch-mutual-pair: DMSA-PrimaryGroup → victim.primary"


def test_postpatch_path_count(lab_paths_expanded):
    """Exactly 6 expanded postpatch-mutual-pair paths expected: 3 containers × 2 targets."""
    postpatch = [p for p in lab_paths_expanded if p.primitive == "postpatch-mutual-pair"]
    assert len(postpatch) == 6, f"Expected 6 postpatch-mutual-pair paths, got {len(postpatch)}"


# ── positive: legacy-oneway-link paths must appear ───────────────────────────

def test_legacy_path_from_direct_container(lab_paths_expanded):
    """DMSA-Direct container must produce legacy paths to all 5 targets."""
    legacy = [
        p for p in lab_paths_expanded
        if p.primitive == "legacy-oneway-link" and p.container_dn == _DIRECT_CONTAINER
    ]
    assert len(legacy) == 5, f"Expected 5 legacy-oneway-link from DMSA-Direct, got {len(legacy)}"


def test_legacy_path_count(lab_paths_expanded):
    """Exactly 15 expanded legacy-oneway-link paths expected: 3 containers × 5 targets."""
    legacy = [p for p in lab_paths_expanded if p.primitive == "legacy-oneway-link"]
    assert len(legacy) == 15, f"Expected 15 legacy-oneway-link paths, got {len(legacy)}"


# ── grouped mode: candidate_targets_count ────────────────────────────────────

def test_grouped_postpatch_target_count(lab_paths_grouped):
    """Grouped postpatch-mutual-pair paths must report candidate_targets_count=2."""
    postpatch = [p for p in lab_paths_grouped if p.primitive == "postpatch-mutual-pair"]
    assert len(postpatch) == 3, f"Expected 3 grouped postpatch paths, got {len(postpatch)}"
    for p in postpatch:
        assert p.candidate_targets_count == 2, (
            f"Expected 2 viable targets for {p.container_dn}, got {p.candidate_targets_count}"
        )
        assert p.requires_operator_target is True
        assert p.target_dn is None


# ── negative: GenericWrite-only container must produce NO path ────────────────

def test_no_path_from_genericwrite_container(lab_paths_expanded):
    """GenericWrite on a container MUST NOT produce any CreateChild-based path."""
    bad = [
        p for p in lab_paths_expanded
        if p.container_dn == _GENERICWRITE_CONTAINER
    ]
    assert bad == [], (
        "Expected no paths from GenericWrite-only container, got: "
        + ", ".join(f"{p.primitive}" for p in bad)
    )


def test_genericwrite_container_no_postpatch(lab_paths_expanded):
    """No postpatch-mutual-pair must originate from DMSA-GenericWriteOnly."""
    bad = [
        p for p in lab_paths_expanded
        if p.primitive == "postpatch-mutual-pair"
        and p.container_dn == _GENERICWRITE_CONTAINER
    ]
    assert bad == []


def test_genericwrite_container_no_legacy(lab_paths_expanded):
    """No legacy-oneway-link must originate from DMSA-GenericWriteOnly."""
    bad = [
        p for p in lab_paths_expanded
        if p.primitive == "legacy-oneway-link"
        and p.container_dn == _GENERICWRITE_CONTAINER
    ]
    assert bad == []


# ── negative: no dacl-* paths for reaper.low (lacks WriteDACL on containers/targets) ──

def test_no_dacl_container_escalate_for_reaper_low(lab_paths_expanded):
    """reaper.low has no WriteDACL on any container — no dacl-container-escalate path."""
    bad = [p for p in lab_paths_expanded if p.primitive == "dacl-container-escalate"]
    assert bad == [], (
        "Expected no dacl-container-escalate for reaper.low, got: "
        + ", ".join(str(p.container_dn) for p in bad)
    )


def test_no_dacl_target_escalate_for_reaper_low(lab_paths_expanded):
    """reaper.low has no WriteDACL on any target — no dacl-target-escalate path."""
    bad = [p for p in lab_paths_expanded if p.primitive == "dacl-target-escalate"]
    assert bad == [], (
        "Expected no dacl-target-escalate for reaper.low, got: "
        + ", ".join(str(p.target_dn) for p in bad)
    )


def test_no_paths_from_empty_rights_containers(lab_paths_expanded):
    """Containers with no rights (DMSA-DACL-Only, DMSA-Nested) must produce no paths."""
    for container in (_DACL_CONTAINER, _NESTED_CONTAINER):
        bad = [p for p in lab_paths_expanded if p.container_dn == container]
        assert bad == [], f"Expected no paths from {container}"


# ── negative: targets without writable_attrs must not appear in postpatch ────

def test_no_postpatch_path_to_victim_legacy(lab_paths_expanded):
    """victim.legacy has no writable superseded attrs — must not appear in postpatch paths."""
    bad = [
        p for p in lab_paths_expanded
        if p.primitive == "postpatch-mutual-pair" and p.target_dn == _VICTIM_LEGACY
    ]
    assert bad == [], "victim.legacy must not be a postpatch target"


def test_no_postpatch_path_to_victim_dacl(lab_paths_expanded):
    """victim.dacl has no writable attrs for reaper.low — must not appear in postpatch paths."""
    bad = [
        p for p in lab_paths_expanded
        if p.primitive == "postpatch-mutual-pair" and p.target_dn == _VICTIM_DACL
    ]
    assert bad == [], "victim.dacl must not be a postpatch target for reaper.low"


def test_no_postpatch_path_to_victim_negative(lab_paths_expanded):
    """victim.negative is a negative control — must never appear in postpatch paths."""
    bad = [
        p for p in lab_paths_expanded
        if p.primitive == "postpatch-mutual-pair" and p.target_dn == _VICTIM_NEGATIVE
    ]
    assert bad == [], "victim.negative must not be a postpatch target"


# ── negative: no existing-dmsa or self-* paths (no dMSAs in fixture) ─────────

def test_no_existing_dmsa_paths(lab_paths_expanded):
    """No existing-dmsa-* paths expected — no dMSA objects in the fixture."""
    bad = [
        p for p in lab_paths_expanded
        if p.primitive.startswith("existing-dmsa")
    ]
    assert bad == []


def test_no_self_paths(lab_paths_expanded):
    """No self-* paths expected — no dMSA objects in the fixture."""
    bad = [
        p for p in lab_paths_expanded
        if p.primitive.startswith("self-")
    ]
    assert bad == []


# ── offline fixture smoke test via CLI ───────────────────────────────────────

def test_offline_fixture_loads_via_cli(tmp_path, monkeypatch):
    """dmsa-reaper map --offline-fixture must produce a valid state JSON from the lab fixture."""
    monkeypatch.chdir(tmp_path)
    from typer.testing import CliRunner
    from dmsa_reaper.cli import app

    out = tmp_path / "state.json"
    runner = CliRunner()
    result = runner.invoke(app, [
        "map",
        "--offline-fixture", str(_FIXTURE),
        "--json", str(out),
        "--domain", "dmsalab.local",
    ])
    assert result.exit_code == 0, result.output
    assert out.exists()
    loaded = MapState.model_validate_json(out.read_text())
    assert loaded.environment.dmsa_capable_status.value == "present"
    assert loaded.current_principal is not None
    assert loaded.current_principal.name == "reaper.low"


def test_paths_command_from_offline_fixture(tmp_path, monkeypatch):
    """dmsa-reaper paths must produce postpatch paths from the offline-loaded state."""
    monkeypatch.chdir(tmp_path)
    import json
    from typer.testing import CliRunner
    from dmsa_reaper.cli import app

    runner = CliRunner()

    state_out = tmp_path / "state.json"
    runner.invoke(app, [
        "map", "--offline-fixture", str(_FIXTURE),
        "--json", str(state_out), "--domain", "dmsalab.local",
    ])

    paths_out = tmp_path / "paths.json"
    result = runner.invoke(app, [
        "paths", "--state", str(state_out), "--expand-targets", "--json", str(paths_out),
    ])
    assert result.exit_code == 0, result.output
    assert paths_out.exists()

    paths = json.loads(paths_out.read_text())
    postpatch = [p for p in paths if p["primitive"] == "postpatch-mutual-pair"]
    assert len(postpatch) == 6, f"Expected 6 postpatch paths, got {len(postpatch)}"

    direct_hit = next(
        (p for p in postpatch
         if "DMSA-Direct" in (p.get("container_dn") or "")
         and "victim.postpatch" in (p.get("target_dn") or "")),
        None,
    )
    assert direct_hit is not None, "DMSA-Direct → victim.postpatch path must appear in CLI output"
