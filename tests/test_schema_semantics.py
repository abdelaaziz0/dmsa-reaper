from dmsa_reaper.constants import DMSA_RELEVANT_ATTRS
from dmsa_reaper.schema.searchflags import is_confidential


def test_confidential_bit_detection():
    assert is_confidential(0x80)
    assert is_confidential(0x81)
    assert not is_confidential(0x40)


def test_msds_managedpassword_not_modeled_as_normal_readable_attr():
    assert "msDS-ManagedPassword" not in DMSA_RELEVANT_ATTRS
