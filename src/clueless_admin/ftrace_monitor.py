import os
from datetime import datetime

import os
import time
import json
from datetime import datetime

TRACING_DIR = "/sys/kernel/debug/tracing"


def call(
    duration: int, frequency: int, output_dir: str = "./ftrace_output"
):
    """
    Calls monitor_ftrace() every 'frequency' seconds for 'duration' seconds,
    and saves the return value as JSON to:
    output_dir / ftrace_monitor_<timestamp> / monitor_ftrace_<timestamp>_<iteration>.json

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
    run_dir = os.path.join(output_dir, f"ftrace_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        try:
            result = monitor_ftrace()
        except Exception as e:
            result = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": {},
                "message": f"Error during monitor_ftrace: {str(e)}",
            }

        iteration = i
        filename = f"monitor_ftrace_{root_timestamp}_{iteration}.json"
        filepath = os.path.join(run_dir, filename)
        try:
            with open(filepath, "w") as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            print(f"Failed to write {filepath}: {e}")

        # Sleep until the next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_ftrace(max_trace_lines: int = 10) -> dict:
    """
    Gather comprehensive ftrace status information for rootkit monitoring.

    Returns JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "ftrace_available": true,
            "tracing_on": true,
            "current_tracer": "function",
            "available_tracers": ["function", ...],
            "enabled_events": ["sched_switch", ...],
            "set_ftrace_filter": ["func1", ...],
            "set_ftrace_notrace": ["func2", ...],
            "trace_options": ["option1", ...],
            "trace_entries": [...],
        },
        "message": "ftrace advanced status retrieved successfully."
    }
    """

    def read_file_lines(path):
        try:
            with open(path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            return []

    def read_file_string(path):
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except Exception:
            return ""

    result = {
        "timestamp": datetime.now().isoformat(),
        "data": {},
        "message": "",
    }

    if not os.path.isdir(TRACING_DIR):
        result["data"] = {
            "ftrace_available": False,
        }
        result["message"] = (
            f"ftrace directory {TRACING_DIR} is not available or not mounted."
        )
        return result

    data = {
        "ftrace_available": True,
        "tracing_on": read_file_string(os.path.join(TRACING_DIR, "tracing_on")) == "1",
        "current_tracer": read_file_string(os.path.join(TRACING_DIR, "current_tracer")),
        "available_tracers": read_file_lines(
            os.path.join(TRACING_DIR, "available_tracers")
        ),
        "enabled_events": read_file_lines(os.path.join(TRACING_DIR, "set_event")),
        "set_ftrace_filter": read_file_lines(
            os.path.join(TRACING_DIR, "set_ftrace_filter")
        ),
        "set_ftrace_notrace": read_file_lines(
            os.path.join(TRACING_DIR, "set_ftrace_notrace")
        ),
        "trace_options": read_file_lines(os.path.join(TRACING_DIR, "trace_options")),
        "trace_entries": [],
    }

    trace_lines = read_file_lines(os.path.join(TRACING_DIR, "trace"))
    if trace_lines:
        data["trace_entries"] = trace_lines[-max_trace_lines:]

    result["data"] = data
    result["message"] = "ftrace advanced status retrieved successfully."
    return result
