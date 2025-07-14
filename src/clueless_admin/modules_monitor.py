import os
from datetime import datetime

def monitor_loaded_modules() -> dict:
    """
    List all loaded modules in the system (lsmod or /proc/modules).
    
    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_modules": 10,
            "modules": [
                {
                    "name": "module1",
                    "size": 12345,
                    "used_by_count": 2,
                    "used_by": ["module2", "module3"],
                    "state": "live",
                    "offset": "0x1234"
                },
                ...
            ]
        },
        "message": "Loaded modules retrieved successfully."
    }
    """
    try:
        with open("/proc/modules", "r") as f:
            content = f.read().strip()
            lines = content.split()
            for line in lines:
                line = line.strip()
                columns = line.split()
                if len(columns) >= 4:
                    used_by = []
                    if len(columns) > 3 and columns[3] != "-":
                        used_by = [
                            dependecy.strip()
                            for dependecy in columns[3].rstrip(",").split(",")
                            if dependecy.strip()
                        ]

                    module_info = {
                        "name": columns[0],
                        "size": int(columns[1]),
                        "used_by_count": int(columns[2]),
                        "used_by": used_by,
                        # Possible states: "live", "unloading", "dead"
                        "state": columns[4] if len(columns) > 4 else "",
                        "offset": columns[5] if len(columns) > 5 else None,
                    }

                    modules.append(module_info)
            total_modules = len(modules)

            return {
                "timestamp": datetime.now().isoformat(),
                "data": {
                    "total_modules": total_modules,
                    "modules": modules,
                },
                "message": "Loaded modules retrieved successfully.",
            }
    except Exception as e:
        return {"timestamp": datetime.now().isoformat(), "data": {}, "message": str(e)}


def list_all_modules() -> dict:
    """
    List all modules in the system, loaded or built (ls /sys/module/).
    Returns a json with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_modules": 10,
            "modules": [
                {
                    "name": "module1",
                    "path": "/sys/module/module1",
                    "state": "active"
                },
                ...
            ]
        },
        "message": "All modules listed successfully."
    }
    """
    try:
        modules = []
        for entry in os.listdir("/sys/module/"):
            module_path = os.path.join("/sys/module/", entry)
            if os.path.isdir(module_path):
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
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {
                "total_modules": len(modules),
                "modules": modules,
            },
            "message": "All modules listed successfully.",
        }
    except Exception as e:
        return {"timestamp": datetime.now().isoformat(), "data": {}, "error": str(e)}


def list_kernel_symbols():
    """List kernel symbols (kallsyms).
    Returns a json with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "symbols": [
                {
                    "address": "0xffffffff81000000",
                    "name": "do_syscall_64",
                    "type": "function"
                },
                ...
            ]
        },
        "message": "Kernel symbols listed successfully."
    }
    """
    try:
        symbols = []
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    address = parts[0]
                    symbol_type = parts[1]
                    name = " ".join(parts[2:])
                    symbols.append({
                        "address": address,
                        "name": name,
                        "type": symbol_type
                    })
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {
                "symbols": symbols
            },
            "message": "Kernel symbols listed successfully."
        }
    except Exception as e:
        return {"timestamp": datetime.now().isoformat(), "data": {}, "error": str(e)}