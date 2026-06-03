from __future__ import annotations

from dmsa_reaper.primitives.base import Primitive
from dmsa_reaper.primitives.dacl_container_escalate import DaclContainerEscalatePrimitive
from dmsa_reaper.primitives.dacl_target_escalate import DaclTargetEscalatePrimitive
from dmsa_reaper.primitives.existing_dmsa_control import (
    ExistingDmsaLegacyLinkPrimitive,
    ExistingDmsaPostPatchMutualPrimitive,
)
from dmsa_reaper.primitives.legacy_oneway_link import LegacyOneWayLinkPrimitive
from dmsa_reaper.primitives.postpatch_mutual_pair import PostPatchMutualPairPrimitive
from dmsa_reaper.primitives.self_pkinit_loop import SelfPkinitLoopPrimitive
from dmsa_reaper.primitives.self_write_map import SelfWriteMapPrimitive


def get_primitives() -> dict[str, Primitive]:
    primitives: list[Primitive] = [
        PostPatchMutualPairPrimitive(),
        ExistingDmsaPostPatchMutualPrimitive(),
        ExistingDmsaLegacyLinkPrimitive(),
        LegacyOneWayLinkPrimitive(),
        DaclContainerEscalatePrimitive(),
        DaclTargetEscalatePrimitive(),
        SelfWriteMapPrimitive(),
        SelfPkinitLoopPrimitive(),
    ]
    return {p.name: p for p in primitives}
