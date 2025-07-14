import os
from datetime import datetime

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

