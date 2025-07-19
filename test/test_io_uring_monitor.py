import os
import pytest
from clueless_admin.io_uring_monitor import monitor_io_uring


@pytest.fixture(scope="session")
def simulate_io_uring_activity():
    """
    Generates io_uring activity by using io_uring-cp if available.
    Requires root privileges and liburing utilities.
    """
    # Path to io_uring-cp (modify as appropriate for your system)
    binary = "/usr/bin/io_uring-cp"
    src = "/etc/hostname"
    dst = "/tmp/hostname_copy_pytest"
    if os.path.exists(binary):
        os.system(f"{binary} {src} {dst}")
    else:
        pytest.skip("io_uring-cp not available; skipping io_uring activity generation.")
    yield
    try:
        os.remove(dst)
    except Exception:
        pass


def test_monitor_io_uring_detects_events(simulate_io_uring_activity):
    """
    Test that monitor_io_uring returns nonzero events after activity.
    """
    result = monitor_io_uring(max_events=3, timeout=2)
    total_events = result["data"].get("total_events", 0)
    assert (
        total_events > 0
    ), f"Expected io_uring events but got {total_events}. Full result: {result}"
    assert isinstance(result["data"]["events"], list)
    assert any(
        "io_uring" in evt for evt in result["data"]["events"]
    ), "No io_uring events detected."
