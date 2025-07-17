import json
import os
import time
from datetime import datetime


async def call(duration: int, frequency: int, output_dir: str = "../data/output"):
    """
    Periodically runs process and thread monitors and stores results in JSON files
    under a time-stamped run directory.

    Each file is named <monitor_name>_<timestamp>_<iteration>.json
    """
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

        monitors = {
            "processes": monitor_process(),
            "threads": monitor_threads(),
        }

        iteration = i
        for monitor_name, result in monitors.items():
            filename = f"{monitor_name}_{root_timestamp}_{iteration}.json"
            filepath = os.path.join(run_dir, filename)
            try:
                with open(filepath, "w") as f:
                    json.dump(result, f, indent=2)
            except Exception as e:
                print(f"Failed to write {filepath}: {e}")

        # Sleep until next scheduled iteration
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_process():
    """
    Monitor process information in the system.

    Reads the /proc filesystem to gather information about running processes.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_processes": 42,
            "processes": [
                {
                    "pid": 1234,
                    "name": "bash",
                    "state": "R",
                    "cpu_usage": 0.5,
                    "memory_usage": 204800
                },
                ...
            ]
        },
        "message": "Processes monitored successfully."
    }
    """
    try:
        processes = []
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    with open(f"/proc/{pid}/stat", "r") as f:
                        stat = f.read().strip().split()
                    with open(f"/proc/{pid}/comm", "r") as f:
                        name = f.read().strip()

                    process_info = {
                        "pid": int(pid),
                        "name": name,
                        "state": stat[2],
                        "cpu_usage": float(stat[13]) + float(stat[14]),  # utime + stime
                        "memory_usage": int(stat[22]) * 4096,  # RSS in pages
                    }
                    processes.append(process_info)
                except Exception:
                    continue

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"total_processes": len(processes), "processes": processes},
            "message": "Processes monitored successfully.",
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error monitoring processes: {str(e)}",
        }


def monitor_threads():
    """
    Monitor thread information in the system.

    Reads the /proc filesystem to gather information about threads of running processes.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_threads": 100,
            "threads": [
                {
                    "tid": 1234,
                    "pid": 5678,
                    "name": "bash",
                    "state": "R",
                    "cpu_usage": 0.5,
                    "memory_usage": 204800
                },
                ...
            ]
        },
        "message": "Threads monitored successfully."
    }
    """
    try:
        threads = []
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    for tid in os.listdir(f"/proc/{pid}/task"):
                        if tid.isdigit():
                            with open(f"/proc/{pid}/task/{tid}/stat", "r") as f:
                                stat = f.read().strip().split()
                            with open(f"/proc/{pid}/task/{tid}/comm", "r") as f:
                                name = f.read().strip()

                            thread_info = {
                                "tid": int(tid),
                                "pid": int(pid),
                                "name": name,
                                "state": stat[2],
                                "cpu_usage": float(stat[13])
                                + float(stat[14]),  # utime + stime
                                "memory_usage": int(stat[22]) * 4096,  # RSS in pages
                            }
                            threads.append(thread_info)
                except Exception:
                    continue

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"total_threads": len(threads), "threads": threads},
            "message": "Threads monitored successfully.",
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error monitoring threads: {str(e)}",
        }
