import pytest
from clueless_admin.ebpf_monitor import monitor_loaded_ebpf


@pytest.fixture(scope="session")
def load_bpftrace_program():
    """
    Loads a temporary eBPF program using bpftrace, if available.
    This requires bpftrace and root privileges.
    """
    import shutil, subprocess, time

    if not shutil.which("bpftrace"):
        pytest.skip("bpftrace not available; skipping eBPF load.")
    import subprocess

    # This will load a simple eBPF program (prints nothing, runs in background)
    proc = subprocess.Popen(
        ["bpftrace", "-e", "interval:s:1 { exit(); }"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)  # Give time for program to load
    yield
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()


def test_monitor_loaded_ebpf_detects_program(load_bpftrace_program):
    """
    Test that monitor_loaded_ebpf detects at least one eBPF program after loading.
    """
    result = monitor_loaded_ebpf()
    programs = result["data"].get("loaded_programs", [])
    assert isinstance(programs, list)
    assert len(programs) > 0, f"No loaded eBPF programs detected. Result: {result}"
