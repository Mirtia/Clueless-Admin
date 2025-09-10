import json
import os
import subprocess
import time
from datetime import datetime
from typing import Any, Dict
from clueless_admin.response import (
    TaskType,
    ErrorCode,
    make_success_response,
    make_error_response,
)


async def call(
    bcc_enabled: bool = False,
    duration: int = 10,
    frequency: int = 1,
    output_dir: str = "data/output",
):
    """
    Calls monitor_loaded_ebpf() every 'frequency' seconds for 'duration' seconds,
    and saves the schema-compliant JSON to:
    output_dir / ebpf_monitor_<timestamp> / monitor_loaded_ebpf_<timestamp>_<iteration>.json

    Parameters:
        bcc_enabled (bool): Argument to be passed to monitor_loaded_ebpf()
        duration (int or float): Total duration of calls in seconds
        frequency (int or float): Interval between calls in seconds
        output_dir (str): Base directory to save the JSON results
    """
    if frequency <= 0:
        # Immediate failure aligned to schema
        resp = make_error_response(
            TaskType.STATE,
            "EBPF_ENUMERATION",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid frequency: {frequency} (must be > 0)",
        )
        raise ValueError(json.dumps(resp))

    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"ebpf_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        try:
            result = monitor_loaded_ebpf(bcc_enabled)
        except Exception as e:
            result = make_error_response(
                TaskType.STATE,
                "EBPF_ENUMERATION",
                ErrorCode.EXECUTION_FAILURE,
                f"Unhandled exception during monitor_loaded_ebpf: {e}",
            )

        # Persist exactly what we produced
        filename = f"monitor_loaded_ebpf_{root_timestamp}_{i}.json"
        filepath = os.path.join(run_dir, filename)

        try:
            with open(filepath, "w") as f:
                json.dump(result, f, indent=2, default=str)
        except Exception as e:
            # Best-effort: write an error file indicating the I/O problem
            io_err = make_error_response(
                TaskType.STATE,
                "EBPF_ENUMERATION",
                ErrorCode.IO_FAILURE,
                f"Failed to write {filepath}: {e}",
            )
            # Attempt to print to stderr/stdout to avoid silent loss
            print(json.dumps(io_err))

        # Sleep until the next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_loaded_ebpf(bcc_enabled: bool = False) -> Dict[str, Any]:
    """
    Enumerates loaded eBPF programs via bpffs (/sys/fs/bpf/) or introspection (bpftool prog list).
    Optionally uses BCC if available and bcc_enabled is True.

    Returns a schema-compliant JSON object:

    SUCCESS:
    {
      "timestamp": "...",
      "status": "SUCCESS",
      "metadata": { "task_type": "STATE", "subtype": "EBPF_ENUMERATION" },
      "data": {
        "loaded_programs": [
           {"id": 12, "type": "kprobe", "name": "handle_sched", "attach_type": "kprobe"}
        ],
        "attachment_points": { "kprobe": [12, 37] }
      }
    }

    FAILURE:
    {
      "timestamp": "...",
      "status": "FAILURE",
      "metadata": { "task_type": "STATE", "subtype": "EBPF_ENUMERATION" },
      "error": { "code": <int>, "message": "<string>" }
    }
    """
    subtype = "EBPF_ENUMERATION"
    data = {"loaded_programs": [], "attachment_points": {}}

    # Prefer bpftool unless the caller explicitly requests BCC
    if not bcc_enabled:
        try:
            bpf_tool_output = subprocess.check_output(
                ["bpftool", "-j", "prog", "list"], text=True
            )
            programs = json.loads(bpf_tool_output)

            for prog in programs:
                prog_id = prog.get("id", "unknown")
                prog_type = prog.get("type", "unknown")
                prog_name = prog.get("name", "unknown")
                attach_type = prog.get("attach_type", "unknown")

                data["loaded_programs"].append(
                    {
                        "id": prog_id,
                        "type": prog_type,
                        "name": prog_name,
                        "attach_type": attach_type,
                    }
                )

                if attach_type not in data["attachment_points"]:
                    data["attachment_points"][attach_type] = []
                # Store IDs only for attachment_points to keep it compact
                if isinstance(prog_id, int) or (
                    isinstance(prog_id, str) and prog_id != "unknown"
                ):
                    data["attachment_points"][attach_type].append(prog_id)

            return make_success_response(TaskType.STATE, subtype, data)

        except FileNotFoundError:
            # bpftool not present; fall through to BCC if allowed or report if bcc_enabled is False
            pass
        except subprocess.CalledProcessError as e:
            return make_error_response(
                TaskType.STATE,
                subtype,
                ErrorCode.EXECUTION_FAILURE,
                f"bpftool failed with exit code {e.returncode}: {e.output or e.stderr}",
            )
        except Exception as e:
            return make_error_response(
                TaskType.STATE,
                subtype,
                ErrorCode.EXECUTION_FAILURE,
                f"Error enumerating eBPF programs via bpftool: {e}",
            )

    # BCC fallback or explicit request
    try:
        from bcc import BPF

        loaded = []
        attachment_points = {}

        kprobes = BPF.get_kprobe_functions(b"")
        loaded.extend(
            [
                {"type": "kprobe", "name": fn, "id": "unknown", "attach_type": "kprobe"}
                for fn in kprobes
            ]
        )
        if kprobes:
            # kprobes list is bytes on some systems; decode conservatively
            kprobe_names = [
                (
                    fn.decode("utf-8", errors="replace")
                    if isinstance(fn, (bytes, bytearray))
                    else fn
                )
                for fn in kprobes
            ]
            attachment_points["kprobe"] = kprobe_names

        data["loaded_programs"] = loaded
        data["attachment_points"] = attachment_points

        return make_success_response(TaskType.STATE, subtype, data)

    except ImportError:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.TOOL_NOT_AVAILABLE,
            "Neither bpftool nor BCC is available for eBPF enumeration.",
        )
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error enumerating eBPF programs via BCC: {e}",
        )
