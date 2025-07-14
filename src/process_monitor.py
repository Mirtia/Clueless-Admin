import datetime
import os

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
