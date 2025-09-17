import json
import os
import time
from datetime import datetime
from typing import Any, Dict

from clueless_admin.response import (
    ErrorCode,
    TaskType,
    make_error_response,
    make_success_response,
)


async def call(duration: int, frequency: int, output_dir: str = "data/output"):
    """
    Periodically runs process and thread monitors and stores results in JSON files
    under a time-stamped run directory.

    Each file is named <monitor_name>_<timestamp>_<iteration>.json
    """
    if frequency <= 0:
        err = make_error_response(
            TaskType.STATE,
            "PROCESS_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid frequency: {frequency} (must be > 0)",
        )
        raise ValueError(json.dumps(err))
    if duration <= 0:
        err = make_error_response(
            TaskType.STATE,
            "PROCESS_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid duration: {duration} (must be > 0)",
        )
        raise ValueError(json.dumps(err))

    os.makedirs(output_dir, exist_ok=True)
    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"process_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        monitors: Dict[str, Dict[str, Any]] = {
            "processes": monitor_process(),
            "threads": monitor_threads(),
        }

        iteration = i
        for monitor_name, result in monitors.items():
            filename = f"{monitor_name}_{root_timestamp}_{iteration}.json"
            filepath = os.path.join(run_dir, filename)
            try:
                with open(filepath, "w") as f:
                    json.dump(result, f, indent=2, default=str)
            except Exception as e:
                io_err = make_error_response(
                    TaskType.STATE,
                    "PROCESS_MONITOR_WRITE",
                    ErrorCode.IO_FAILURE,
                    f"Failed to write {filepath}: {e}",
                )
                print(json.dumps(io_err))

        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def _page_size() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, ValueError):
        return 4096


def monitor_process() -> Dict[str, Any]:
    """
    Enumerate processes via /proc.

    SUCCESS data:
      {
        "count": <int>,
        "page_size": <int>,
        "processes": [
          {
            "pid": <int>,
            "name": "<str>",
            "state": "<char>",
            "rss_pages": <int|null>,
            "rss_bytes": <int|null>
          }, ...
        ]
      }
    """
    subtype = "PROCESSES"
    try:
        processes = []
        page_sz = _page_size()

        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/stat", "r") as f:
                    raw = f.read().strip()

                lpar = raw.rfind("(")
                rpar = raw.rfind(")")
                if lpar == -1 or rpar == -1 or rpar < lpar:
                    parts = raw.split()
                    state = parts[2] if len(parts) > 2 else "?"
                    rss_pages = int(parts[23]) if len(parts) > 23 else None
                    name = "<unknown>"
                else:
                    name = raw[lpar + 1 : rpar]
                    rest = raw[:lpar].split() + raw[rpar + 1 :].split()
                    state = rest[2] if len(rest) > 2 else "?"
                    rss_pages = int(rest[23]) if len(rest) > 23 else None

                rss_bytes = rss_pages * page_sz if isinstance(rss_pages, int) else None

                processes.append(
                    {
                        "pid": int(pid),
                        "name": name,
                        "state": state,
                        "rss_pages": int(rss_pages) if rss_pages is not None else None,
                        "rss_bytes": int(rss_bytes) if rss_bytes is not None else None,
                    }
                )
            except Exception:
                continue

        data = {
            "count": len(processes),
            "page_size": int(page_sz),
            "processes": processes,
        }
        return make_success_response(TaskType.STATE, subtype, data)

    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error monitoring processes: {e}",
        )


def monitor_threads() -> Dict[str, Any]:
    """
    Enumerate threads via /proc/[pid]/task/*.

    SUCCESS data:
      {
        "total_threads": <int>,
        "page_size": <int>,
        "threads": [
          {
            "tid": <int>,
            "pid": <int>,
            "name": "<str>",
            "state": "<char>",
            "rss_pages": <int|null>,
            "rss_bytes": <int|null>
          }, ...
        ]
      }
    """
    subtype = "THREADS"
    try:
        threads = []
        page_sz = _page_size()

        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            task_dir = f"/proc/{pid}/task"
            if not os.path.isdir(task_dir):
                continue

            try:
                tids = [t for t in os.listdir(task_dir) if t.isdigit()]
            except Exception:
                continue

            for tid in tids:
                try:
                    with open(f"{task_dir}/{tid}/stat", "r") as f:
                        raw = f.read().strip()

                    lpar = raw.rfind("(")
                    rpar = raw.rfind(")")
                    if lpar == -1 or rpar == -1 or rpar < lpar:
                        parts = raw.split()
                        state = parts[2] if len(parts) > 2 else "?"
                        rss_pages = int(parts[23]) if len(parts) > 23 else None
                        name = "<unknown>"
                    else:
                        name = raw[lpar + 1 : rpar]
                        rest = raw[:lpar].split() + raw[rpar + 1 :].split()
                        state = rest[2] if len(rest) > 2 else "?"
                        rss_pages = int(rest[23]) if len(rest) > 23 else None

                    rss_bytes = (
                        rss_pages * page_sz if isinstance(rss_pages, int) else None
                    )

                    threads.append(
                        {
                            "tid": int(tid),
                            "pid": int(pid),
                            "name": name,
                            "state": state,
                            "rss_pages": (
                                int(rss_pages) if rss_pages is not None else None
                            ),
                            "rss_bytes": (
                                int(rss_bytes) if rss_bytes is not None else None
                            ),
                        }
                    )
                except Exception:
                    continue

        data = {
            "total_threads": len(threads),
            "page_size": int(page_sz),
            "threads": threads,
        }
        return make_success_response(TaskType.STATE, subtype, data)

    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error monitoring threads: {e}",
        )
