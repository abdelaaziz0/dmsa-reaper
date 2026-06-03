import pytest

from dmsa_reaper.ops.operation_log import configure_ops_dir


@pytest.fixture(autouse=True)
def _reset_operation_log_dir():
    configure_ops_dir(None)
    yield
    configure_ops_dir(None)
