"""Tests for scope enforcement."""
from __future__ import annotations

import json

import pytest

from dmsa_reaper.scope import (
    Scope,
    check_domain_match,
    check_dn_in_scope,
    is_dn_denied,
    is_dn_in_allowed_scope,
    load_scope,
)


# ── Scope model loading ───────────────────────────────────────────────────────

def test_load_scope_from_json(tmp_path):
    data = {
        "domain": "corp.local",
        "allowedOUs": ["OU=Reaper,DC=corp,DC=local"],
        "allowedTargets": ["OU=Targets,DC=corp,DC=local"],
        "denyTargets": ["CN=krbtgt,CN=Users,DC=corp,DC=local"],
        "denySubtrees": ["OU=Blocked,DC=corp,DC=local"],
        "allowDaclPrimitives": False,
        "allowBroadDacl": False,
    }
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(data))
    scope, digest = load_scope(scope_file)
    assert scope.domain == "corp.local"
    assert "OU=Reaper,DC=corp,DC=local" in scope.allowed_ous
    assert "OU=Targets,DC=corp,DC=local" in scope.allowed_targets
    assert "CN=krbtgt,CN=Users,DC=corp,DC=local" in scope.deny_targets
    assert "OU=Blocked,DC=corp,DC=local" in scope.deny_subtrees
    assert len(digest) == 64  # sha256 hex


def test_load_scope_returns_stable_hash(tmp_path):
    data = {"domain": "corp.local", "allowedOUs": [], "allowedTargets": [], "denyTargets": []}
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(data))
    _, h1 = load_scope(scope_file)
    _, h2 = load_scope(scope_file)
    assert h1 == h2


# ── DN containment (is_dn_in_allowed_scope) ───────────────────────────────────

def _scope(**kw) -> Scope:
    defaults = dict(domain="corp.local", allowed_ous=[], allowed_targets=[], deny_targets=[])
    defaults.update(kw)
    return Scope.model_validate(defaults, from_attributes=True)


def test_dn_under_allowed_ou_passes():
    scope = _scope(allowed_ous=["OU=Reaper,DC=corp,DC=local"])
    assert is_dn_in_allowed_scope("CN=dmsa-1234,OU=Reaper,DC=corp,DC=local", scope, created=True)


def test_dn_equal_to_allowed_ou_passes():
    scope = _scope(allowed_ous=["OU=Reaper,DC=corp,DC=local"])
    assert is_dn_in_allowed_scope("OU=Reaper,DC=corp,DC=local", scope, created=True)


def test_dn_not_under_allowed_ou_fails():
    scope = _scope(allowed_ous=["OU=Reaper,DC=corp,DC=local"])
    assert not is_dn_in_allowed_scope("CN=dmsa-1234,OU=Other,DC=corp,DC=local", scope, created=True)


def test_dn_case_insensitive():
    scope = _scope(allowed_ous=["OU=Reaper,DC=corp,DC=local"])
    assert is_dn_in_allowed_scope("CN=dmsa,OU=reaper,DC=CORP,DC=LOCAL", scope, created=True)


def test_created_dn_in_allowed_targets_only_not_allowed():
    """created=True must check only allowedOUs, not allowedTargets."""
    scope = _scope(
        allowed_ous=["OU=Reaper,DC=corp,DC=local"],
        allowed_targets=["OU=Targets,DC=corp,DC=local"],
    )
    assert not is_dn_in_allowed_scope("CN=svc,OU=Targets,DC=corp,DC=local", scope, created=True)


def test_modified_dn_in_allowed_targets_passes():
    """created=False allows allowedTargets as well as allowedOUs."""
    scope = _scope(
        allowed_ous=["OU=Reaper,DC=corp,DC=local"],
        allowed_targets=["OU=Targets,DC=corp,DC=local"],
    )
    assert is_dn_in_allowed_scope("CN=svc,OU=Targets,DC=corp,DC=local", scope, created=False)


# ── denyTargets ───────────────────────────────────────────────────────────────

def test_deny_targets_blocks_exact_dn():
    scope = _scope(deny_targets=["CN=krbtgt,CN=Users,DC=corp,DC=local"])
    assert is_dn_denied("CN=krbtgt,CN=Users,DC=corp,DC=local", scope)


def test_deny_targets_case_insensitive():
    scope = _scope(deny_targets=["CN=krbtgt,CN=Users,DC=corp,DC=local"])
    assert is_dn_denied("CN=KRBTGT,CN=Users,DC=CORP,DC=LOCAL", scope)


def test_deny_targets_does_not_block_child():
    """denyTargets blocks exact matches only, not subtree children."""
    scope = _scope(deny_targets=["CN=Users,DC=corp,DC=local"])
    assert not is_dn_denied("CN=krbtgt,CN=Users,DC=corp,DC=local", scope)


def test_deny_subtree_blocks_child_dn():
    scope = _scope(
        allowed_ous=["OU=Allowed,DC=corp,DC=local"],
        deny_subtrees=["OU=Allowed,DC=corp,DC=local"],
    )
    assert is_dn_denied("CN=x,OU=Allowed,DC=corp,DC=local", scope)


def test_deny_subtree_overrides_allowed_ou():
    scope = _scope(
        allowed_ous=["OU=Allowed,DC=corp,DC=local"],
        deny_subtrees=["OU=Allowed,DC=corp,DC=local"],
    )
    with pytest.raises(ValueError, match="denied"):
        check_dn_in_scope("CN=x,OU=Allowed,DC=corp,DC=local", scope, created=True)


def test_default_sensitive_system_container_blocked():
    scope = _scope(
        allowed_ous=["CN=System,DC=corp,DC=local"],
        allowed_targets=["CN=System,DC=corp,DC=local"],
    )
    assert is_dn_denied("CN=AdminSDHolder,CN=System,DC=corp,DC=local", scope)


# ── check_domain_match ────────────────────────────────────────────────────────

def test_domain_match_passes():
    scope = _scope(domain="corp.local")
    check_domain_match("corp.local", scope)  # no exception


def test_domain_match_case_insensitive():
    scope = _scope(domain="corp.local")
    check_domain_match("CORP.LOCAL", scope)  # no exception


def test_domain_mismatch_raises():
    scope = _scope(domain="corp.local")
    with pytest.raises(ValueError, match="corp.local"):
        check_domain_match("evil.com", scope)


def test_domain_match_none_mapped_domain_passes():
    scope = _scope(domain="corp.local")
    check_domain_match(None, scope)  # no exception — unknown mapped domain is permitted


# ── check_dn_in_scope ─────────────────────────────────────────────────────────

def test_check_dn_blocked_by_deny():
    scope = _scope(
        allowed_ous=["OU=Reaper,DC=corp,DC=local"],
        deny_targets=["CN=krbtgt,CN=Users,DC=corp,DC=local"],
    )
    with pytest.raises(ValueError, match="denied"):
        check_dn_in_scope("CN=krbtgt,CN=Users,DC=corp,DC=local", scope, created=False)


def test_check_dn_blocked_by_out_of_scope():
    scope = _scope(allowed_ous=["OU=Reaper,DC=corp,DC=local"])
    with pytest.raises(ValueError, match="allowedOUs"):
        check_dn_in_scope("CN=dmsa,OU=Other,DC=corp,DC=local", scope, created=True)


def test_check_dn_in_scope_passes_silently():
    scope = _scope(allowed_ous=["OU=Reaper,DC=corp,DC=local"])
    check_dn_in_scope("CN=dmsa-1234,OU=Reaper,DC=corp,DC=local", scope, created=True)


# ── Primitive preflight scope integration ────────────────────────────────────

def test_preflight_scope_blocks_container_outside_scope():
    """preflight() must raise PrimitiveError when the container is outside allowedOUs."""
    from dmsa_reaper.models import PathCandidate
    from dmsa_reaper.primitives.postpatch_mutual_pair import PostPatchMutualPairPrimitive
    from dmsa_reaper.primitives.base import PrimitiveError

    prim = PostPatchMutualPairPrimitive()
    path = PathCandidate(
        id="P-0001",
        primitive="postpatch-mutual-pair",
        principal="S-1-5-21-1-2-3-500",
        container_dn="OU=Evil,DC=corp,DC=local",
        requires_modify_dmsa=True,
        requires_modify_target=True,
    )
    scope = _scope(allowed_ous=["OU=Reaper,DC=corp,DC=local"])
    with pytest.raises(PrimitiveError, match="scope"):
        prim.preflight(path, scope=scope, target_dn="CN=svc,OU=Reaper,DC=corp,DC=local")


def test_preflight_scope_passes_when_in_scope(tmp_path, monkeypatch):
    """preflight() must return without error when all DNs are in scope."""
    monkeypatch.chdir(tmp_path)
    from dmsa_reaper.models import PathCandidate
    from dmsa_reaper.primitives.postpatch_mutual_pair import PostPatchMutualPairPrimitive

    prim = PostPatchMutualPairPrimitive()
    path = PathCandidate(
        id="P-0001",
        primitive="postpatch-mutual-pair",
        principal="S-1-5-21-1-2-3-500",
        container_dn="OU=Reaper,DC=corp,DC=local",
        requires_modify_dmsa=True,
        requires_modify_target=True,
    )
    scope = _scope(
        allowed_ous=["OU=Reaper,DC=corp,DC=local"],
        allowed_targets=["OU=Reaper,DC=corp,DC=local"],
    )
    # Should not raise
    warnings = prim.preflight(
        path, scope=scope, target_dn="CN=svc,OU=Reaper,DC=corp,DC=local"
    )
    assert isinstance(warnings, list)


def test_preflight_no_scope_always_passes():
    """preflight(scope=None) must always return an empty warnings list."""
    from dmsa_reaper.models import PathCandidate
    from dmsa_reaper.primitives.legacy_oneway_link import LegacyOneWayLinkPrimitive

    prim = LegacyOneWayLinkPrimitive()
    path = PathCandidate(
        id="P-0001",
        primitive="legacy-oneway-link",
        principal="S-1-5-21-1-2-3-500",
        container_dn="OU=AnyOU,DC=corp,DC=local",
    )
    warnings = prim.preflight(path, scope=None)
    assert warnings == []
