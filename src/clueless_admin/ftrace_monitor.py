import json
import os
import time
from datetime import datetime

# See: https://www.kernel.org/doc/html/latest/trace/ftrace.html
TRACING_DIR = "/sys/kernel/debug/tracing"

# Debugfs is a special susbystem in linux designed to
# expose kernel space information / logs to userspace.
# It is generally mounted at /sys/kernel/debug.

from clueless_admin.response import (
    ErrorCode,
    TaskType,
    make_error_response,
    make_success_response,
)


async def call(
    duration: int,
    frequency: int,
    max_trace_lines: int = 100,
    output_dir: str = "data/output",
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
    # Validate inputs with schema-compliant errors
    if frequency <= 0:
        err = make_error_response(
            TaskType.STATE,
            "FTRACE_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid frequency: {frequency} (must be > 0)",
        )
        raise ValueError(json.dumps(err))
    if duration <= 0:
        err = make_error_response(
            TaskType.STATE,
            "FTRACE_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid duration: {duration} (must be > 0)",
        )
        raise ValueError(json.dumps(err))
    if max_trace_lines is not None and max_trace_lines < 0:
        err = make_error_response(
            TaskType.STATE,
            "FTRACE_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid max_trace_lines: {max_trace_lines} (must be >= 0 or None)",
        )
        raise ValueError(json.dumps(err))

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
            result = monitor_ftrace(max_trace_lines=max_trace_lines)
        except Exception as e:
            result = make_error_response(
                TaskType.STATE,
                "FTRACE_STATUS",
                ErrorCode.EXECUTION_FAILURE,
                f"Unhandled exception during monitor_ftrace: {e}",
            )

        iteration = i
        filename = f"monitor_ftrace_{root_timestamp}_{iteration}.json"
        filepath = os.path.join(run_dir, filename)
        try:
            with open(filepath, "w") as f:
                json.dump(result, f, indent=2, default=str)
        except Exception as e:
            io_err = make_error_response(
                TaskType.STATE,
                "FTRACE_MONITOR_WRITE",
                ErrorCode.IO_FAILURE,
                f"Failed to write {filepath}: {e}",
            )
            # Emit to stdout to avoid silent loss
            print(json.dumps(io_err))

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

    subtype = "FTRACE_STATUS"

    if not os.path.isdir(TRACING_DIR):
        # ftrace not available / debugfs not mounted
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.IO_FAILURE,
            f"ftrace directory {TRACING_DIR} is not available or not mounted.",
        )

    try:
        data = {
            "ftrace_available": True,
            "tracing_on": read_file_string(os.path.join(TRACING_DIR, "tracing_on"))
            == "1",
            "current_tracer": read_file_string(
                os.path.join(TRACING_DIR, "current_tracer")
            ),
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
            "trace_options": read_file_lines(
                os.path.join(TRACING_DIR, "trace_options")
            ),
            "trace_entries": [],
        }

        trace_lines = read_file_lines(os.path.join(TRACING_DIR, "trace"))
        if trace_lines and max_trace_lines is not None and max_trace_lines > 0:
            data["trace_entries"] = trace_lines[-max_trace_lines:]

        return make_success_response(TaskType.STATE, subtype, data)

    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error collecting ftrace status: {e}",
        )
