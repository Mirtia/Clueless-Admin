import json
import os
import time
from datetime import datetime
from typing import Iterable, Optional


async def call(
    duration: int,
    frequency: int,
    known_directories_file: Optional[str] = "/data/input/directory_list.txt",
    output_dir: str = "data/output",
):
    """
    Periodically runs all monitor functions and saves their outputs
    in a per-run subdirectory under output_dir, with the run directory named by the root timestamp.
    Each file is named <monitor>_<timestamp>_<iteration>.json for traceability.
    """
    os.makedirs(output_dir, exist_ok=True)
    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"file_system_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        monitors = {
            "file_descriptors": monitor_file_descriptors(),
            "known_directories": (
                monitor_known_directories(
                    known_directories_file=known_directories_file, has_input_file=True
                )
                if known_directories_file
                else monitor_known_directories(has_input_file=False)
            ),
            "file_systems": monitor_file_systems(),
        }
        # Iteration count: i+1 (or i if you want zero-based)
        iteration = i
        for monitor_name, result in monitors.items():
            filename = f"{monitor_name}_{root_timestamp}_{iteration}.json"
            filepath = os.path.join(run_dir, filename)
            try:
                with open(filepath, "w") as f:
                    json.dump(result, f, indent=2)
            except Exception as e:
                print(f"Failed to write {filepath}: {e}")

        # Sleep until the next interval
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_file_descriptors():
    """
    Monitor file descriptors in the system.

    Reads the /proc filesystem to gather information about open file descriptors for each process.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_processes": 100,
            "processes": [
                {
                    "pid": 1234,
                    "fd_count": 10,
                    "fds": [
                        {
                            "fd": 0,
                            "type": "REG",
                            "path": "/path/to/file"
                        },
                        ...
                    ]
                },
                ...
            ]
        },
        "message": "File descriptors monitored successfully."
    }
    """
    try:
        processes = []
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    fd_dir = f"/proc/{pid}/fd"
                    if os.path.exists(fd_dir):
                        fds = []
                        for fd in os.listdir(fd_dir):
                            fd_path = os.readlink(os.path.join(fd_dir, fd))
                            fd_type = (
                                "REG"
                                if os.path.isfile(fd_path)
                                else "DIR" if os.path.isdir(fd_path) else "OTHER"
                            )
                            fds.append(
                                {"fd": int(fd), "type": fd_type, "path": fd_path}
                            )

                        processes.append(
                            {"pid": int(pid), "fd_count": len(fds), "fds": fds}
                        )
                except Exception:
                    continue

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"total_processes": len(processes), "processes": processes},
            "message": "File descriptors monitored successfully.",
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error monitoring file descriptors: {str(e)}",
        }


# def monitor_inodes():
#     """
#     Monitor inodes in the system.

#     Reads the /proc filesystem to gather information about inodes and their usage.

#     Returns a JSON with the following structure:
#     {
#         "timestamp": "2025-10-01T12:00:00",
#         "data": {
#             "total_inodes": 1000,
#             "inodes": [
#                 {
#                     "inode": 123456,
#                     "path": "/path/to/file",
#                     "type": "REG",
#                     "size": 2048
#                 },
#                 ...
#             ]
#         },
#         "message": "Inodes monitored successfully."
#     }
#     """
#     try:
#         inodes = []
#         for root, dirs, files in os.walk("/"):
#             for name in files + dirs:
#                 path = os.path.join(root, name)
#                 try:
#                     stat_info = os.stat(path)
#                     inodes.append(
#                         {
#                             "inode": stat_info.st_ino,
#                             "path": path,
#                             "type": "REG" if os.path.isfile(path) else "DIR",
#                             "size": stat_info.st_size,
#                         }
#                     )
#                 except Exception:
#                     continue

#         return {
#             "timestamp": datetime.now().isoformat(),
#             "data": {"total_inodes": len(inodes), "inodes": inodes},
#             "message": "Inodes monitored successfully.",
#         }

#     except Exception as e:
#         return {
#             "timestamp": datetime.now().isoformat(),
#             "data": {},
#             "message": f"Error monitoring inodes: {str(e)}",
#         }


def monitor_known_directories(
    known_directories_file: Optional[str] = None,
    has_input_file: bool = False,
    known_directories: Optional[dict[str]] = {"/dev", "/tmp", "/sys"},
) -> dict:
    """
    Monitor known directories in the system.

    Args:
        known_directories_file (str, optional): Path to file containing directory paths to monitor.
        has_input_file (bool): If True, use directories listed in known_directories_file.
        known_directories (Iterable[str], optional): List or set of directories to monitor if not using input file.

    Returns:
        dict: JSON-like dict containing timestamp, directory contents, and status message.
    """
    try:
        if has_input_file:
            if not known_directories_file or not os.path.isfile(known_directories_file):
                raise ValueError(
                    "known_directories_file must be a valid path if has_input_file is True."
                )
            with open(known_directories_file, "r") as f:
                directories = [line.strip() for line in f if line.strip()]
        else:
            if known_directories is None:
                raise ValueError(
                    "known_directories must be provided if has_input_file is False."
                )
            directories = list(known_directories)

        directories_info = []
        for directory in directories:
            if os.path.exists(directory) and os.path.isdir(directory):
                try:
                    contents = os.listdir(directory)
                except Exception as e:
                    contents = [f"Error reading directory: {str(e)}"]
                directories_info.append({"path": directory, "contents": contents})
            else:
                directories_info.append(
                    {
                        "path": directory,
                        "contents": ["Directory does not exist or is not a directory."],
                    }
                )

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": {"directories": directories_info},
            "message": "Known directories monitored successfully.",
        }
    except Exception as e:
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": {},
            "message": f"Error monitoring known directories: {str(e)}",
        }


def monitor_file_systems():
    """
    Monitor file systems in the system.

    Reads the /proc/filesystems and /etc/fstab to gather information about mounted file systems.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_filesystems": 5,
            "filesystems": [
                {
                    "type": "ext4",
                    "mount_point": "/",
                    "options": "rw,relatime"
                },
                ...
            ]
        },
        "message": "File systems monitored successfully."
    }
    """
    try:
        filesystems = []
        with open("/proc/filesystems", "r") as f:
            for line in f:
                if line.startswith("nodev"):
                    continue
                fs_type = line.strip()
                mount_point = None
                options = None

                # Check /etc/fstab for mount point and options
                with open("/etc/fstab", "r") as fstab:
                    for fstab_line in fstab:
                        if fs_type in fstab_line:
                            parts = fstab_line.split()
                            if len(parts) >= 2:
                                mount_point = parts[1]
                                options = parts[3] if len(parts) > 3 else ""

                filesystems.append(
                    {"type": fs_type, "mount_point": mount_point, "options": options}
                )

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"total_filesystems": len(filesystems), "filesystems": filesystems},
            "message": "File systems monitored successfully.",
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error monitoring file systems: {str(e)}",
        }
