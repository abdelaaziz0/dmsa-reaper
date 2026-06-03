from __future__ import annotations

from ldap3.protocol.microsoft import security_descriptor_control

from dmsa_reaper.constants import DEFAULT_SD_FLAGS


def sd_control(sdflags: int = DEFAULT_SD_FLAGS):
    return security_descriptor_control(sdflags=sdflags)
