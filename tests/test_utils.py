from dmsa_reaper.schema.searchflags import is_confidential
from dmsa_reaper.utils import bytes_to_guid_le, guid_to_bytes_le, parse_int_auto


def test_guid_roundtrip_le():
    guid = "0feb936f-47b3-49f2-9386-1dedc2c23765"
    assert bytes_to_guid_le(guid_to_bytes_le(guid)) == guid


def test_confidential_searchflags():
    assert is_confidential(0x80)
    assert is_confidential(0x280)
    assert not is_confidential(0x0)


def test_parse_int_auto():
    assert parse_int_auto("0x5") == 5
    assert parse_int_auto("5") == 5
