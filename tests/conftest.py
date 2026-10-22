"""Shared test setup, as in unseenet's own tests."""
import pytest

from unseenet.core import ripening


@pytest.fixture(autouse=True)
def state_dir(tmp_path, monkeypatch):
    """Keys' state files go to the test's folder, never ~/.unseenet."""
    monkeypatch.setenv("UNSEENET_STATE_DIR", str(tmp_path / "keys"))


@pytest.fixture(autouse=True)
def fast_ripening():
    """Key ripening (UN-RFC 0025) with thresholds divided by 2^16 and no rules."""
    ripening.scale_for_tests(16, rules=False)
    yield
    ripening.scale_for_tests(0)


@pytest.fixture
def ripening_rules():
    """The real rules (surcharges, floor, nodes requiring level 0), fast thresholds."""
    ripening.scale_for_tests(16)
    yield
