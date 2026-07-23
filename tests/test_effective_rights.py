from dmsa_reaper.acl.ace_matcher import Ace
from dmsa_reaper.acl.effective_rights import has_effective_right


def test_explicit_allow_before_inherited_deny_is_effective():
    aces = [
        Ace(sid="S-1-5-21-X-1000", ace_type="allow", rights={"WriteProperty"}),
        Ace(
            sid="S-1-5-21-X-1000",
            ace_type="deny",
            rights={"WriteProperty"},
            inherited=True,
        ),
    ]
    assert has_effective_right(aces, {"S-1-5-21-X-1000"}, "WriteProperty")


def test_explicit_deny_before_allow_blocks_right():
    aces = [
        Ace(sid="S-1-5-21-X-1000", ace_type="deny", rights={"WriteProperty"}),
        Ace(sid="S-1-5-21-X-1000", ace_type="allow", rights={"WriteProperty"}),
    ]
    assert not has_effective_right(aces, {"S-1-5-21-X-1000"}, "WriteProperty")


def test_owner_implied_writedacl():
    assert has_effective_right([], {"S-1-5-21-X-1000"}, "WriteDACL", owner_sid="S-1-5-21-X-1000")


def test_object_specific_create_child():
    guid = "0feb936f-47b3-49f2-9386-1dedc2c23765"
    aces = [Ace(sid="S-1-5-21-X-1000", ace_type="allow", rights={"CreateChild"}, object_type_guid=guid)]
    assert has_effective_right(aces, {"S-1-5-21-X-1000"}, "CreateChild", object_type_guid=guid)
    assert not has_effective_right(aces, {"S-1-5-21-X-1000"}, "CreateChild", object_type_guid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
