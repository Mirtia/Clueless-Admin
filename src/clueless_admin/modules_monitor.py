import json
import os
import time
from datetime import datetime

from clueless_admin.response import (
    ErrorCode,
    TaskType,
    make_error_response,
    make_success_response,
)


async def call(duration: int, frequency: int, output_dir: str = "data/output"):
    """
    Calls module monitors every 'frequency' seconds for 'duration' seconds,
    and saves each monitor's return value as JSON to:
    output_dir / modules_monitor_<timestamp> / <monitor>_<timestamp>_<iteration>.json

    Parameters:
        duration (int or float): Total duration of calls in seconds.
        frequency (int or float): Interval between calls in seconds.
        output_dir (str): Base directory to save the JSON results.
    """
    # Validate inputs
    if frequency <= 0:
        err = make_error_response(
            TaskType.STATE,
            "MODULES_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid frequency: {frequency} (must be > 0)",
        )
        raise ValueError(json.dumps(err))
    if duration <= 0:
        err = make_error_response(
            TaskType.STATE,
            "MODULES_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid duration: {duration} (must be > 0)",
        )
        raise ValueError(json.dumps(err))

    os.makedirs(output_dir, exist_ok=True)
    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"modules_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        monitors = {
            "monitor_loaded_modules": monitor_loaded_modules(),
            "monitor_all_loaded_modules": monitor_all_loaded_modules(),
            "list_kernel_symbols": list_kernel_symbols(),
        }

        iteration = i
        # TODO: Pass iteration number to response.
        for monitor_name, result in monitors.items():
            filename = f"{monitor_name}_{root_timestamp}_{iteration}.json"
            filepath = os.path.join(run_dir, filename)
            try:
                with open(filepath, "w") as f:
                    json.dump(result, f, indent=2, default=str)
            except Exception as e:
                io_err = make_error_response(
                    TaskType.STATE,
                    "MODULES_MONITOR_WRITE",
                    ErrorCode.IO_FAILURE,
                    f"Failed to write {filepath}: {e}",
                )
                # Best-effort emission to stdout to avoid silent loss
                print(json.dumps(io_err))

        # Sleep until the next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_loaded_modules() -> dict:
    """
    List all loaded modules in the system (/proc/modules).
    """
    subtype = "LOADED_MODULES"
    try:
        modules = []
        with open("/proc/modules", "r") as f:
            for line in f:
                columns = line.strip().split()
                if len(columns) < 4:
                    continue
                used_by = []
                if columns[3] != "-":
                    used_by = [
                        dep.strip()
                        for dep in columns[3].rstrip(",").split(",")
                        if dep.strip()
                    ]
                module_info = {
                    "name": columns[0],
                    "size": int(columns[1]),
                    "used_by_count": int(columns[2]),
                    "used_by": used_by,
                    # Possible states: "live", "unloading", "dead"
                    "state": columns[4] if len(columns) > 4 else "",
                    # Given KASLR, virtual memory address offset.
                    "offset": columns[5] if len(columns) > 5 else None,
                }
                modules.append(module_info)

        data = {"total_modules": len(modules), "modules": modules}
        return make_success_response(TaskType.STATE, subtype, data)

    except FileNotFoundError as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.IO_FAILURE,
            f"/proc/modules not found: {e}",
        )
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error reading /proc/modules: {e}",
        )


def monitor_all_loaded_modules() -> dict:
    """
    List all modules in the system, loaded or built (ls /sys/module/).
    """
    subtype = "ALL_MODULES"
    try:
        modules = []
        base = "/sys/module/"
        if not os.path.isdir(base):
            return make_error_response(
                TaskType.STATE,
                subtype,
                ErrorCode.IO_FAILURE,
                f"{base} is not a directory or not accessible.",
            )

        for entry in os.listdir(base):
            module_path = os.path.join(base, entry)
            if not os.path.isdir(module_path):
                continue

            refcnt_path = os.path.join(module_path, "refcnt")
            initstate_path = os.path.join(module_path, "initstate")
            holders_path = os.path.join(module_path, "holders")
            # TODO: Test thoroughly with different modules.
            if os.path.exists(refcnt_path):
                state = "loaded"  # Dynamically loaded module
            elif os.path.exists(initstate_path):
                state = "loaded"  # Module with init state
            elif os.path.exists(holders_path):
                state = "loaded"  # Has dependency tracking
            else:
                state = "builtin"

            module_info = {
                "name": entry,
                "path": module_path,
                "state": state,
            }
            modules.append(module_info)

        data = {"total_modules": len(modules), "modules": modules}
        return make_success_response(TaskType.STATE, subtype, data)

    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error listing /sys/module: {e}",
        )


def list_kernel_symbols() -> dict:
    """
    List kernel symbols (/proc/kallsyms). May require permissions depending on kptr_restrict.
    """
    subtype = "KERNEL_SYMBOLS"
    try:
        symbols = []
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                address = parts[0]
                symbol_type = parts[1]
                name = " ".join(parts[2:])
                symbols.append({"address": address, "name": name, "type": symbol_type})

        data = {"symbols": symbols}
        return make_success_response(TaskType.STATE, subtype, data)

    except FileNotFoundError as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.IO_FAILURE,
            f"/proc/kallsyms not found: {e}",
        )
    except PermissionError as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.IO_FAILURE,
            f"Permission denied reading /proc/kallsyms (kptr_restrict?): {e}",
        )
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error reading /proc/kallsyms: {e}",
        )
