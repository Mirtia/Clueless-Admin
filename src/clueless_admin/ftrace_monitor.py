
import os
from datetime import datetime

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
        result["message"] = f"ftrace directory {TRACING_DIR} is not available or not mounted."
        return result

    data = {
        "ftrace_available": True,
        "tracing_on": read_file_string(os.path.join(TRACING_DIR, "tracing_on")) == "1",
        "current_tracer": read_file_string(os.path.join(TRACING_DIR, "current_tracer")),
        "available_tracers": read_file_lines(os.path.join(TRACING_DIR, "available_tracers")),
        "enabled_events": read_file_lines(os.path.join(TRACING_DIR, "set_event")),
        "set_ftrace_filter": read_file_lines(os.path.join(TRACING_DIR, "set_ftrace_filter")),
        "set_ftrace_notrace": read_file_lines(os.path.join(TRACING_DIR, "set_ftrace_notrace")),
        "trace_options": read_file_lines(os.path.join(TRACING_DIR, "trace_options")),
        "trace_entries": [],
    }

    trace_lines = read_file_lines(os.path.join(TRACING_DIR, "trace"))
    if trace_lines:
        data["trace_entries"] = trace_lines[-max_trace_lines:]

    result["data"] = data
    result["message"] = "ftrace advanced status retrieved successfully."
    return result