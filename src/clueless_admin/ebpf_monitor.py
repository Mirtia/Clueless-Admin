import json
import os
import subprocess
import time
from datetime import datetime
from typing import Any, Dict

def call(
    bcc_enabled: bool = False,
    duration: int = 10,
    frequency: int = 1,
    output_dir: str = "../../data/output",
):
    """
    Calls monitor_loaded_ebpf() every 'frequency' seconds for 'duration' seconds,
    and saves the return value as JSON to:
    output_dir / ebpf_monitor_<timestamp> / monitor_loaded_ebpf_<timestamp>_<iteration>.json

    Parameters:
        bcc_enabled (bool): Argument to be passed to monitor_loaded_ebpf()
        duration (int or float): Total duration of calls in seconds
        frequency (int or float): Interval between calls in seconds
        output_dir (str): Base directory to save the JSON results
    """
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
            result = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": {},
                "message": f"Error during monitor_loaded_ebpf: {str(e)}",
            }

        iteration = i
        filename = f"monitor_loaded_ebpf_{root_timestamp}_{iteration}.json"
        filepath = os.path.join(run_dir, filename)

        try:
            with open(filepath, "w") as f:
                json.dump(result, f, indent=2, default=str)
        except Exception as e:
            print(f"Failed to write {filepath}: {e}")

        # Sleep until the next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_loaded_ebpf(bcc_enabled: bool = False) -> Dict[str, Any]:
    """
    Enumerates loaded eBPF programs via bpffs (/sys/fs/bpf/) or introspection (bpftool prog list).
    Optionally uses BCC if available and bcc_enabled is True.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "loaded_programs": [...],
            "attachment_points": {...},
        },
        "message": "Placeholder message."
    }
    """
    timestamp = datetime.now().isoformat()
    data = {"loaded_programs": [], "attachment_points": {}}
    # Try bpftool first unless bcc_enabled is True
    if not bcc_enabled:
        try:
            # Try to enumerate loaded programs using bpftool
            bpf_tool_output = subprocess.check_output(
                ["bpftool", "-j", "prog", "list"], text=True
            )
            import json

            programs = json.loads(bpf_tool_output)
            for prog in programs:
                # Other attributes (type, id, name, etc)
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
                # Track attachment points
                if attach_type not in data["attachment_points"]:
                    data["attachment_points"][attach_type] = []
                data["attachment_points"][attach_type].append(prog_id)
            return {
                "timestamp": timestamp,
                "data": data,
                "message": "eBPF programs enumerated successfully via bpftool.",
            }
        except FileNotFoundError:
            print(
                "Warning: bpftool is not installed or not found in PATH. Falling back to BCC."
            )
            pass
        except Exception as e:
            return {
                "timestamp": timestamp,
                "data": {},
                "message": f"Error enumerating eBPF programs via bpftool: {str(e)}",
            }
    try:
        # BCC fallback
        from bcc import BPF

        loaded = []
        attachment_points = {}
        kprobes = BPF.get_kprobe_functions("")
        loaded.extend([{"type": "kprobe", "name": fn} for fn in kprobes])
        if kprobes:
            attachment_points["kprobe"] = list(kprobes)

        data["loaded_programs"] = loaded
        data["attachment_points"] = attachment_points
        return {
            "timestamp": timestamp,
            "data": data,
            "message": "eBPF programs enumerated via BCC (limited introspection).",
        }
    except ImportError:
        return {
            "timestamp": timestamp,
            "data": {},
            "message": "Neither bpftool nor BCC is available for eBPF enumeration.",
        }
    except Exception as e:
        return {
            "timestamp": timestamp,
            "data": {},
            "message": f"Error enumerating eBPF programs via BCC: {str(e)}",
        }
