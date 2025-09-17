import json
import os
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from clueless_admin.response import (
    ErrorCode,
    TaskType,
    make_error_response,
    make_success_response,
)

KALLSYMS_PATH = "/proc/kallsyms"
KPTR_RESTRICT_PATH = "/proc/sys/kernel/kptr_restrict"


async def call(
    duration: int,
    frequency: int,
    output_dir: str = "data/output",
    filter_regex: Optional[str] = None,
    module_regex: Optional[str] = None,
    max_symbols: Optional[int] = 5000,
):
    """
    Periodically snapshot kallsyms every 'frequency' seconds for 'duration' seconds.
    Writes JSON files under:
        output_dir / kallsyms_monitor_<root_ts> / kallsyms_<root_ts>_<iteration>.json
    """
    # Validate inputs
    if frequency <= 0:
        err = make_error_response(
            TaskType.STATE,
            "KALLSYMS_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid frequency: {frequency} (must be > 0)",
        )
        raise ValueError(json.dumps(err))
    if duration <= 0:
        err = make_error_response(
            TaskType.STATE,
            "KALLSYMS_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid duration: {duration} (must be > 0)",
        )
        raise ValueError(json.dumps(err))
    if max_symbols is not None and max_symbols < 0:
        err = make_error_response(
            TaskType.STATE,
            "KALLSYMS_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid max_symbols: {max_symbols} (must be >= 0 or None)",
        )
        raise ValueError(json.dumps(err))

    os.makedirs(output_dir, exist_ok=True)

    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"kallsyms_monitor_{root_ts}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()

    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        try:
            snap = snapshot_kallsyms(
                filter_regex=filter_regex,
                module_regex=module_regex,
                max_symbols=max_symbols,
            )
        except Exception as e:
            snap = make_error_response(
                TaskType.STATE,
                "KALLSYMS_SNAPSHOT",
                ErrorCode.EXECUTION_FAILURE,
                f"Unhandled exception during kallsyms snapshot: {e}",
            )

        filename = f"kallsyms_{root_ts}_{i}.json"
        filepath = os.path.join(run_dir, filename)
        try:
            with open(filepath, "w") as f:
                json.dump(snap, f, indent=2, default=str)
        except Exception as e:
            io_err = make_error_response(
                TaskType.STATE,
                "KALLSYMS_MONITOR_WRITE",
                ErrorCode.IO_FAILURE,
                f"Failed to write {filepath}: {e}",
            )
            # Emit to stdout as a last resort
            print(json.dumps(io_err))

        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def _read_kptr_restrict() -> Optional[int]:
    try:
        with open(KPTR_RESTRICT_PATH, "r") as f:
            return int(f.read().strip())
    except Exception:
        return None


def _parse_kallsyms_line(line: str) -> Optional[Dict[str, Optional[str]]]:
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if len(parts) < 3:
        return None

    addr = parts[0]
    sym_type = parts[1]
    module = None
    if parts[-1].startswith("[") and parts[-1].endswith("]"):
        module = parts[-1].strip("[]")
        name = " ".join(parts[2:-1]) if len(parts) > 3 else parts[2]
    else:
        name = " ".join(parts[2:])

    return {"addr": addr, "type": sym_type, "name": name, "module": module}


def _compile_regex(
    pattern: Optional[str],
) -> Tuple[Optional[re.Pattern], Optional[str]]:
    if pattern is None:
        return None, None
    try:
        return re.compile(pattern), None
    except re.error as e:
        return None, f"Invalid regex '{pattern}': {e}"


def snapshot_kallsyms(
    filter_regex: Optional[str] = None,
    module_regex: Optional[str] = None,
    max_symbols: Optional[int] = None,
) -> Dict:
    """
    Take a snapshot of /proc/kallsyms with optional filters.
    Returns a schema-compliant SUCCESS or FAILURE object.
    """
    subtype = "KALLSYMS_SNAPSHOT"

    # Regex compilation
    name_re, name_err = _compile_regex(filter_regex)
    if name_err:
        return make_error_response(
            TaskType.STATE, subtype, ErrorCode.INVALID_ARGUMENTS, name_err
        )
    mod_re, mod_err = _compile_regex(module_regex)
    if mod_err:
        return make_error_response(
            TaskType.STATE, subtype, ErrorCode.INVALID_ARGUMENTS, mod_err
        )

    kptr = _read_kptr_restrict()

    if not os.path.exists(KALLSYMS_PATH):
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.IO_FAILURE,
            f"{KALLSYMS_PATH} not found. This kernel/distro may not expose kallsyms.",
        )

    symbols: List[Dict[str, Optional[str]]] = []
    total_after_filter = 0
    try:
        with open(KALLSYMS_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                rec = _parse_kallsyms_line(line)
                if not rec:
                    continue

                # Apply filters
                if name_re and not name_re.search(rec["name"] or ""):
                    continue
                if mod_re:
                    m = rec["module"] if rec["module"] is not None else ""
                    if not mod_re.search(m):
                        continue

                total_after_filter += 1

                # Cap returned list but keep counting totals
                if max_symbols is not None and len(symbols) >= max_symbols:
                    continue

                symbols.append(rec)
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error reading {KALLSYMS_PATH}: {e}",
        )

    data = {
        "total_symbols": total_after_filter,
        "returned_symbols": len(symbols),
        "kptr_restrict": kptr,
        "filters": {
            "name_regex": filter_regex or "",
            "module_regex": module_regex or "",
            "max_symbols": max_symbols,
        },
        "symbols": symbols,
    }

    return make_success_response(TaskType.STATE, subtype, data)
