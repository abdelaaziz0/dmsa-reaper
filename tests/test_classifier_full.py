"""Tests for all path classifiers including new primitives."""

from dmsa_reaper.models import (
    ContainerObject,
    DmsaObject,
    Environment,
    MapState,
    Right,
    SchemaCache,
    TargetObject,
)
from dmsa_reaper.paths.classifier import classify_paths
from dmsa_reaper.paths.ranking import rank_paths

PSID = "S-1-5-21-X-1000"
DMSA_DN = "CN=dmsa1,CN=Managed Service Accounts,DC=corp,DC=local"
CONTAINER_DN = "OU=Apps,DC=corp,DC=local"
TARGET_DN = "CN=svc-backup,CN=Users,DC=corp,DC=local"


def _env(capable: bool = True) -> Environment:
    return Environment(dmsa_capable=capable)


def _right(right_name: str, dn: str = CONTAINER_DN) -> Right:
    return Right(principal_sid=PSID, right=right_name, object_dn=dn)


# ── postpatch-mutual-pair ─────────────────────────────────────────────────────

def test_postpatch_mutual_pair_detected():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[
            ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])
        ],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = classify_paths(state)
    primitive_names = [p.primitive for p in paths]
    assert "postpatch-mutual-pair" in primitive_names


def test_postpatch_not_detected_when_target_attrs_missing():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=[TargetObject(dn=TARGET_DN, writable_attrs=["msDS-SupersededManagedAccountLink"])],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "postpatch-mutual-pair"]
    assert paths == []


def test_postpatch_not_detected_when_dmsa_not_capable():
    state = MapState(
        environment=_env(capable=False),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "postpatch-mutual-pair"]
    assert paths == []


# ── existing-dMSA primitives ──────────────────────────────────────────────────

def test_existing_dmsa_postpatch_generic_all_with_target_attrs():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(dn=DMSA_DN, rights=[_right("GenericAll", DMSA_DN)])
        ],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths
    assert paths[0].dmsa_dn == DMSA_DN


def test_existing_dmsa_postpatch_not_detected_without_target_attrs():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[_right("WriteProperty:msDS-KeyCredentialLink", DMSA_DN)],
            )
        ],
        targets=[TargetObject(dn=TARGET_DN, writable_attrs=["msDS-SupersededManagedAccountLink"])],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths == []


def test_existing_dmsa_only_keycredentiallink_does_not_emit_postpatch():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[_right("WriteProperty:msDS-KeyCredentialLink", DMSA_DN)],
            )
        ],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths == []


def test_existing_dmsa_only_groupmsamembership_does_not_emit_postpatch():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[_right("WriteProperty:msDS-GroupMSAMembership", DMSA_DN)],
            )
        ],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths == []


def test_existing_dmsa_only_writedacl_does_not_emit_direct_postpatch():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[DmsaObject(dn=DMSA_DN, rights=[_right("WriteDACL", DMSA_DN)])],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths == []


def test_existing_dmsa_preceded_by_without_state_does_not_emit():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[_right("WriteProperty:msDS-ManagedAccountPrecededByLink", DMSA_DN)],
            )
        ],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths == []


def test_existing_dmsa_state_without_preceded_by_does_not_emit():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[_right("WriteProperty:msDS-DelegatedMSAState", DMSA_DN)],
            )
        ],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths == []


def test_existing_dmsa_both_specific_attrs_and_target_attrs_emit_postpatch():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[
                    _right("WriteProperty:msDS-ManagedAccountPrecededByLink", DMSA_DN),
                    _right("WriteProperty:msDS-DelegatedMSAState", DMSA_DN),
                ],
            )
        ],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths


def test_existing_dmsa_generic_write_and_target_attrs_emit_postpatch():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[DmsaObject(dn=DMSA_DN, rights=[_right("GenericWrite", DMSA_DN)])],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths


def test_existing_dmsa_generic_all_and_target_attrs_emit_postpatch():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[DmsaObject(dn=DMSA_DN, rights=[_right("GenericAll", DMSA_DN)])],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    assert paths


def test_existing_dmsa_no_dangerous_rights():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(dn=DMSA_DN, rights=[_right("ReadProperty", DMSA_DN)])
        ],
    )
    postpatch = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-postpatch-mutual"]
    legacy = [p for p in classify_paths(state) if p.primitive == "existing-dmsa-legacy-link"]
    assert postpatch == []
    assert legacy == []


# ── legacy-oneway-link ────────────────────────────────────────────────────────

def test_legacy_oneway_link_detected():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=[TargetObject(dn=TARGET_DN)],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "legacy-oneway-link"]
    assert paths
    assert not paths[0].requires_modify_target


def test_legacy_oneway_link_not_when_no_capable():
    state = MapState(
        environment=_env(capable=False),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=[TargetObject(dn=TARGET_DN)],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "legacy-oneway-link"]
    assert paths == []


# ── self-write-map ─────────────────────────────────────────────────────────────
# self-write-map is classified from self_rights (what the dMSA can do to itself),
# not from the operator's rights.  This distinguishes "operator controls dMSA"
# (existing-dMSA control) from "dMSA can write its own sensitive attributes".

def test_self_write_map_detected():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                self_rights=[_right("WriteProperty:msDS-KeyCredentialLink", DMSA_DN)],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "self-write-map"]
    assert paths
    assert paths[0].executable is False


def test_self_write_map_not_when_no_write_surface():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[DmsaObject(dn=DMSA_DN)],  # self_rights is empty
    )
    paths = [p for p in classify_paths(state) if p.primitive == "self-write-map"]
    assert paths == []


def test_self_write_map_not_triggered_by_operator_rights():
    """Operator having WriteProperty on the dMSA must not create a self-write-map path."""
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[_right("WriteProperty:msDS-KeyCredentialLink", DMSA_DN)],
                # self_rights is empty — the dMSA cannot write itself
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "self-write-map"]
    assert paths == []


# ── self-pkinit-loop ──────────────────────────────────────────────────────────

def test_self_pkinit_loop_detected():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                self_rights=[
                    _right("WriteProperty:msDS-KeyCredentialLink", DMSA_DN),
                    _right("WriteProperty:msDS-GroupMSAMembership", DMSA_DN),
                ],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "self-pkinit-loop"]
    assert paths
    assert paths[0].executable is False


def test_self_pkinit_loop_requires_both_rights():
    # Only KeyCredentialLink in self_rights — not sufficient for pkinit-loop.
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                self_rights=[_right("WriteProperty:msDS-KeyCredentialLink", DMSA_DN)],
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "self-pkinit-loop"]
    assert paths == []


def test_self_pkinit_loop_not_triggered_by_operator_rights():
    """Operator having both rights must not create a self-pkinit-loop path."""
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn=DMSA_DN,
                rights=[
                    _right("WriteProperty:msDS-KeyCredentialLink", DMSA_DN),
                    _right("WriteProperty:msDS-GroupMSAMembership", DMSA_DN),
                ],
                # self_rights is empty
            )
        ],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "self-pkinit-loop"]
    assert paths == []


# ── ranking ───────────────────────────────────────────────────────────────────

def test_ranking_order():
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
        dmsas=[
            DmsaObject(dn=DMSA_DN, rights=[_right("GenericWrite", DMSA_DN)])
        ],
    )
    paths = rank_paths(classify_paths(state))
    # postpatch-mutual-pair should come before legacy-oneway-link.
    primitives = [p.primitive for p in paths]
    assert primitives.index("postpatch-mutual-pair") < primitives.index("legacy-oneway-link")
    # existing-dmsa-postpatch-mutual before self-write-map.
    if "existing-dmsa-postpatch-mutual" in primitives and "self-write-map" in primitives:
        assert primitives.index("existing-dmsa-postpatch-mutual") < primitives.index("self-write-map")


# ── grouping / explosion guard ────────────────────────────────────────────────

def _multi_target_state(n_targets: int = 5) -> "MapState":
    from dmsa_reaper.models import MapState
    targets = [
        TargetObject(
            dn=f"CN=svc{i},{TARGET_DN.split(',', 1)[1]}",
            writable_attrs=[
                "msDS-SupersededManagedAccountLink",
                "msDS-SupersededServiceAccountState",
            ],
        )
        for i in range(n_targets)
    ]
    return MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=targets,
    )


def test_postpatch_grouped_by_container_not_per_target():
    """Default classify_paths must emit one postpatch path per container, not per target."""
    state = _multi_target_state(5)
    paths = [p for p in classify_paths(state) if p.primitive == "postpatch-mutual-pair"]
    assert len(paths) == 1, f"expected 1 grouped path, got {len(paths)}"
    assert paths[0].candidate_targets_count == 5
    assert paths[0].target_dn is None


def test_postpatch_expand_targets_emits_one_per_target():
    """expand_targets=True must emit one postpatch path per target."""
    state = _multi_target_state(5)
    paths = [p for p in classify_paths(state, expand_targets=True) if p.primitive == "postpatch-mutual-pair"]
    assert len(paths) == 5
    for p in paths:
        assert p.target_dn is not None
        assert p.candidate_targets_count == 0


def test_legacy_grouped_by_container_not_per_target():
    """Default classify_paths must emit one legacy path per container, not per target."""
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=[TargetObject(dn=f"CN=t{i},DC=corp,DC=local") for i in range(4)],
    )
    paths = [p for p in classify_paths(state) if p.primitive == "legacy-oneway-link"]
    assert len(paths) == 1, f"expected 1 grouped path, got {len(paths)}"
    assert paths[0].candidate_targets_count == 4
    assert paths[0].target_dn is None


def test_legacy_expand_targets_emits_one_per_target():
    """expand_targets=True must emit one legacy path per target."""
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[ContainerObject(dn=CONTAINER_DN, rights=[_right("CreateChild:dMSA")])],
        targets=[TargetObject(dn=f"CN=t{i},DC=corp,DC=local") for i in range(3)],
    )
    paths = [p for p in classify_paths(state, expand_targets=True) if p.primitive == "legacy-oneway-link"]
    assert len(paths) == 3
    for p in paths:
        assert p.target_dn is not None


def test_two_containers_two_grouped_paths():
    """One grouped path must be emitted per container, not one globally."""
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        containers=[
            ContainerObject(dn="OU=A,DC=corp,DC=local", rights=[_right("CreateChild:dMSA", "OU=A,DC=corp,DC=local")]),
            ContainerObject(dn="OU=B,DC=corp,DC=local", rights=[_right("CreateChild:dMSA", "OU=B,DC=corp,DC=local")]),
        ],
        targets=[TargetObject(dn=f"CN=t{i},DC=corp,DC=local") for i in range(3)],
    )
    legacy = [p for p in classify_paths(state) if p.primitive == "legacy-oneway-link"]
    assert len(legacy) == 2
    container_dns = {p.container_dn for p in legacy}
    assert container_dns == {"OU=A,DC=corp,DC=local", "OU=B,DC=corp,DC=local"}


# ── requires_operator_target ──────────────────────────────────────────────────

def test_existing_dmsa_paths_require_operator_target():
    """Grouped existing-dMSA paths must have requires_operator_target=True."""
    state = MapState(
        environment=_env(),
        schema_cache=SchemaCache(),
        dmsas=[DmsaObject(dn=DMSA_DN, rights=[_right("GenericAll", DMSA_DN)])],
        targets=[
            TargetObject(
                dn=TARGET_DN,
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = [
        p for p in classify_paths(state)
        if p.primitive in {"existing-dmsa-postpatch-mutual", "existing-dmsa-legacy-link"}
    ]
    assert paths
    assert all(p.requires_operator_target is True for p in paths)


def test_grouped_postpatch_and_legacy_require_operator_target():
    """Grouped (default) postpatch and legacy paths have no target_dn baked in —
    they must carry requires_operator_target=True so the CLI demands --target-dn."""
    state = _multi_target_state(1)
    for p in classify_paths(state):
        if p.primitive in ("postpatch-mutual-pair", "legacy-oneway-link"):
            assert p.requires_operator_target is True, (
                f"{p.primitive} grouped path must have requires_operator_target=True"
            )


def test_expanded_postpatch_and_legacy_do_not_require_operator_target():
    """Expanded paths (expand_targets=True) embed the target DN, so they must NOT
    carry requires_operator_target=True."""
    state = _multi_target_state(1)
    for p in classify_paths(state, expand_targets=True):
        if p.primitive in ("postpatch-mutual-pair", "legacy-oneway-link"):
            assert p.requires_operator_target is False, (
                f"{p.primitive} expanded path must have requires_operator_target=False"
            )
            assert p.target_dn is not None
