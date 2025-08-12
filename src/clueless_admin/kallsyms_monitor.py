import json
import os
import re
import time
from datetime import datetime
from typing import Dict, List, Optional

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

    Parameters:
        duration: total runtime in seconds.
        frequency: interval between snapshots in seconds.
        output_dir: base directory for JSON results.
        filter_regex: optional regex on symbol names.
        module_regex: optional regex on module names (None means core kernel).
        max_symbols: cap symbols returned per snapshot.
    """
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
            snap = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": {},
                "message": f"Error during kallsyms snapshot: {e}",
            }

        filename = f"kallsyms_{root_ts}_{i}.json"
        filepath = os.path.join(run_dir, filename)
        try:
            with open(filepath, "w") as f:
                json.dump(snap, f, indent=2)
        except Exception as e:
            print(f"Error: Failed to write {filepath}: {e}")

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


def snapshot_kallsyms(
    filter_regex: Optional[str] = None,
    module_regex: Optional[str] = None,
    max_symbols: Optional[int] = None,
) -> Dict:
    kptr = _read_kptr_restrict()

    if not os.path.exists(KALLSYMS_PATH):
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": {},
            "message": f"{KALLSYMS_PATH} not found. This kernel/distro may not expose kallsyms.",
        }

    name_re = re.compile(filter_regex) if filter_regex else None
    mod_re = re.compile(module_regex) if module_regex else None

    symbols: List[Dict[str, Optional[str]]] = []
    total_after_filter = 0
    try:
        with open(KALLSYMS_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                rec = _parse_kallsyms_line(line)
                if not rec:
                    continue

                if name_re and not name_re.search(rec["name"] or ""):
                    continue
                if mod_re:
                    m = rec["module"] if rec["module"] is not None else ""
                    if not mod_re.search(m):
                        continue

                total_after_filter += 1
                symbols.append(rec)
                if max_symbols is not None and len(symbols) >= max_symbols:
                    continue
    except Exception as e:
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": {},
            "message": f"Error reading {KALLSYMS_PATH}: {e}",
        }

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "data": {
            "total_symbols": total_after_filter,
            "returned_symbols": len(symbols),
            "kptr_restrict": kptr,
            "symbols": symbols,
        },
        "message": (
            "kallsyms snapshot collected successfully."
            if symbols
            else "No symbols matched filters or output is restricted."
        ),
    }
