from dmsa_reaper.map.environment import compute_dmsa_capable_status
from dmsa_reaper.map.kds import kds_root_key_status
from dmsa_reaper.models import CheckStatus, Environment


def test_dmsa_capable_status_truth_table():
    assert compute_dmsa_capable_status(
        CheckStatus.present,
        CheckStatus.present,
        CheckStatus.present,
    ) == CheckStatus.present
    assert compute_dmsa_capable_status(
        CheckStatus.present,
        CheckStatus.absent,
        CheckStatus.present,
    ) == CheckStatus.absent
    assert compute_dmsa_capable_status(
        CheckStatus.present,
        CheckStatus.unknown,
        CheckStatus.present,
    ) == CheckStatus.unknown


def test_kds_root_key_absent_means_not_dmsa_capable():
    assert compute_dmsa_capable_status(
        CheckStatus.present,
        CheckStatus.present,
        CheckStatus.absent,
    ) == CheckStatus.absent


def test_kds_query_failure_is_unknown():
    class _Conn:
        entries = []

        def search(self, **kwargs):
            raise RuntimeError("bind lost")

    assert kds_root_key_status(_Conn(), "CN=Configuration,DC=corp,DC=local") == CheckStatus.unknown


def test_environment_compat_booleans_sync_to_status():
    env = Environment(dmsa_capable=True, has_kds_root_key=True)
    assert env.dmsa_capable_status == CheckStatus.present
    assert env.kds_root_key_status == CheckStatus.present
