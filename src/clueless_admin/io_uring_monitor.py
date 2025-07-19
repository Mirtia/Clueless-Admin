import json
import os
import time
from datetime import datetime

# Globals
FTRACE_PATH = "/sys/kernel/debug/tracing"
FTRACE_PIPE = os.path.join(FTRACE_PATH, "trace_pipe")
FTRACE_FILTER = os.path.join(FTRACE_PATH, "set_ftrace_filter")
FTRACE_TRACER = os.path.join(FTRACE_PATH, "current_tracer")
FTRACE_ON = os.path.join(FTRACE_PATH, "tracing_on")


async def call(
    duration: int,
    frequency: int,
    max_events=50,
    timeout=5,
    output_dir: str = "data/output",
):
    """
    Calls monitor_io_uring() every 'frequency' seconds for 'duration' seconds,
    and saves the return value as JSON to:
    output_dir / io_uring_monitor_<timestamp> / monitor_io_uring_<timestamp>_<iteration>.json

    Parameters:
        duration (int or float): Total duration of calls in seconds.
        frequency (int or float): Interval between calls in seconds.
        output_dir (str): Base directory to save the JSON results.
    """
    os.makedirs(output_dir, exist_ok=True)
    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"io_uring_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        try:
            result = monitor_io_uring(max_events, timeout)
        except Exception as e:
            result = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": {},
                "message": f"Error during monitor_io_uring: {str(e)}",
            }

        iteration = i
        filename = f"monitor_io_uring_{root_timestamp}_{iteration}.json"
        filepath = os.path.join(run_dir, filename)
        try:
            with open(filepath, "w") as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            print(f"Error: Failed to write {filepath}: {e}")

        # Sleep until the next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def setup_ftrace_io_uring():
    """
    Configure ftrace to monitor io_uring-related syscalls.
    Only adds functions not already in the filter.
    """
    # Step 1: Get available io_uring-related function names
    with open(os.path.join(FTRACE_PATH, "available_filter_functions")) as f:
        filter_funcs = f.read()
    available_functions = set(
        line.strip().split()[0]
        for line in filter_funcs.splitlines()
        if "io_uring" in line
    )

    if not available_functions:
        raise RuntimeError("No io_uring-related functions found.")

    # Step 2: Read current set_ftrace_filter contents (may be empty)
    current_functions = set()
    if os.path.exists(FTRACE_FILTER):
        with open(FTRACE_FILTER, "r") as f:
            current_functions = set(line.strip() for line in f if line.strip())

    # Step 3: Find which functions are new (not already set)
    to_add = available_functions - current_functions

    if not to_add:
        print("Log: No new io_uring functions to add; filter already up to date.")
    else:
        with open(FTRACE_FILTER, "a") as f:
            for func in sorted(to_add):
                f.write(func + "\n")
        print(f"Log: Added {len(to_add)} io_uring functions to set_ftrace_filter.")

    with open(FTRACE_ON, "w") as f:
        f.write("0\n")
    with open(os.path.join(FTRACE_PATH, "available_tracers")) as f:
        available = f.read()
    if "function" not in available:
        raise RuntimeError('"function" tracer not available on this kernel.')
    with open(FTRACE_TRACER, "w") as f:
        f.write("function\n")
    # Enable after filter setup is complete.
    with open(FTRACE_ON, "w") as f:
        f.write("1\n")


def monitor_io_uring(max_events=50, timeout=5):
    """
    Monitor io_uring usage in the system via ftrace.

    Collect up to max_events or until timeout seconds have elapsed,
    whichever comes first.

    Returns a JSON object with the following structure:
    {
        "timestamp": "...",
        "data": {"total_events": ..., "events": [...]},
        "message": ...
    }
    """
    try:
        if not os.path.exists(FTRACE_PIPE):
            return {
                "timestamp": datetime.now().isoformat(),
                "data": {},
                "message": (
                    "ftrace trace_pipe not found. Root privileges and a mounted debugfs "
                    "are required for kernel-level io_uring event monitoring."
                ),
            }

        try:
            setup_ftrace_io_uring()
        except Exception as e:
            return {
                "timestamp": datetime.now().isoformat(),
                "data": {},
                "message": f"Failed to configure ftrace for io_uring monitoring: {str(e)}",
            }

        events = []
        start_time = time.time()
        with open(FTRACE_PIPE, "r") as f:
            while len(events) < max_events:
                # Wait for data or timeout
                rlist, _, _ = select.select([f], [], [], timeout)
                if not rlist:
                    # Timed out waiting for more events
                    break
                line = f.readline()
                if not line:
                    break
                events.append(line.strip())
                # Optional: break if overall time limit exceeded
                if time.time() - start_time > timeout:
                    break

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {
                "total_events": len(events),
                "events": events,
            },
            "message": (
                f"io_uring events monitored successfully via ftrace. "
                f"{len(events)} events collected."
                if events
                else "No io_uring events detected in ftrace output."
            ),
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error during io_uring ftrace monitoring: {str(e)}",
        }


# == Notes ==
# On io_uring rootkit: 0 syscalls is of course not possible, but the idea is to prove that the rootkit is not using any syscalls that are related to the attack,
# only the io_uring syscalls are used.
# On system calls: Once you place one or more SQEs on to the SQ, you need to
# let the kernel know that you've done so. You can do this
# by calling the io_uring_enter(2) system call.
# See more: https://man7.org/linux/man-pages/man7/io_uring.7.html
# Known rootkit will use this method with the only visible syscalls being the io_uring.
# Possible false positives: Some known modules that use the io_uring is qemu and nginx.
