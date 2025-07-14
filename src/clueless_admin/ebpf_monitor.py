import subprocess
from datetime import datetime
from typing import Dict, Any
from bcc import BPF
from bcc import BPF_NO_PRELOAD
from bcc import BPFModule
from bcc import BPFPerfEvent
from bcc import BPFPerfEventArray
from bcc import BPFPerfEventMap
from bcc import BPFMap
from bcc import BPFProgram
from bcc import BPFTable
from bcc import BPFTrace


def monitor_loaded_ebpf(use_bcc: bool = False) -> Dict[str, Any]:
    """
    Enumerates loaded eBPF programs via bpffs (/sys/fs/bpf/) or introspection (bpftool prog list).
    Optionally uses BCC if available and use_bcc is True.

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
    # Try bpftool first unless use_bcc is True
    if not use_bcc:
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
