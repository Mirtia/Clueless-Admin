import json
import os
import time
from datetime import datetime


async def call(duration: int, frequency: int, output_dir: str = "data/output"):
    """
    Calls monitor_io_uring() every 'frequency' seconds for 'duration' seconds,
    and saves the return value as JSON to:
    output_dir / io_uring_monitor_<timestamp> / monitor_io_uring_<timestamp>_<iteration>.json

    Parameters:
        duration (int or float): Total duration of calls in seconds.
        frequency (int or float): Interval between calls in seconds.
        output_dir (str): Base directory to save the JSON results.
    """
    os.makedirs(output_dir, exist_ok=True)
    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"io_uring_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        try:
            result = monitor_io_uring()
        except Exception as e:
            result = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": {},
                "message": f"Error during monitor_io_uring: {str(e)}",
            }

        iteration = i
        filename = f"monitor_io_uring_{root_timestamp}_{iteration}.json"
        filepath = os.path.join(run_dir, filename)
        try:
            with open(filepath, "w") as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            print(f"Failed to write {filepath}: {e}")

        # Sleep until the next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_io_uring():
    """
    Monitor io_uring usage in the system.

    Reads the /proc/io_uring file to gather information about io_uring instances.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_instances": 3,
            "instances": [
                {
                    "instance_id": "12345",
                    "sq_size": 1024,
                    "cq_size": 1024,
                    "flags": "0x0"
                },
                ...
            ]
        },
        "message": "io_uring instances monitored successfully."
    }
    """
    try:
        # Read /proc/io_uring
        with open("/proc/io_uring", "r") as f:
            content = f.read().strip()

        if not content:
            return {
                "timestamp": datetime.now().isoformat(),
                "data": {"total_instances": 0, "instances": []},
                "message": "No io_uring instances found.",
            }

        instances = []
        for line in content.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue

            instance = {
                "instance_id": parts[0],
                "sq_size": int(parts[1]),
                "cq_size": int(parts[2]),
                "flags": parts[3] if len(parts) > 3 else "",
            }
            instances.append(instance)

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"total_instances": len(instances), "instances": instances},
            "message": "io_uring instances monitored successfully.",
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error monitoring io_uring: {str(e)}",
        }


# == Notes ==
# 0 syscalls is of course not possible, but the idea is to prove that the rootkit is not using any syscalls that are related to the attack,
# only the io_uring syscalls are used.
# Once you place one or more SQEs on to the SQ, you need to
# let the kernel know that you've done so. You can do this
# by calling the io_uring_enter(2) system call.
# https://man7.org/linux/man-pages/man7/io_uring.7.html
# Known rootkit will use this method with the only visible syscalls being the io_uring.
# Some known modules that use the io_uring is qemu and nginx.
