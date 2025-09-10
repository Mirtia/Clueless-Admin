# file_system_monitor.py
import json
import os
import time
from datetime import datetime
from typing import Iterable, Optional, Dict, Any
from clueless_admin.response import (
    TaskType,
    ErrorCode,
    make_success_response,
    make_error_response,
    iso_utc_timestamp,
)


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
    if frequency <= 0:
        # Surface as a structured error via an exception payload
        err = make_error_response(
            TaskType.STATE,
            "FILE_SYSTEM_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid frequency: {frequency} (must be > 0)",
        )
        raise ValueError(json.dumps(err))

    if duration <= 0:
        err = make_error_response(
            TaskType.STATE,
            "FILE_SYSTEM_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid duration: {duration} (must be > 0)",
        )
        raise ValueError(json.dumps(err))

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

        monitors: Dict[str, Dict[str, Any]] = {
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

        iteration = i
        for monitor_name, result in monitors.items():
            filename = f"{monitor_name}_{root_timestamp}_{iteration}.json"
            filepath = os.path.join(run_dir, filename)
            try:
                with open(filepath, "w") as f:
                    json.dump(result, f, indent=2, default=str)
            except Exception as e:
                # Best-effort structured error emission to stdout to avoid silent loss
                io_err = make_error_response(
                    TaskType.STATE,
                    "FILE_SYSTEM_MONITOR_WRITE",
                    ErrorCode.IO_FAILURE,
                    f"Failed to write {filepath}: {e}",
                )
                print(json.dumps(io_err))

        # Sleep until the next interval
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def monitor_file_descriptors() -> Dict[str, Any]:
    """
    Monitor file descriptors in the system by traversing /proc/<pid>/fd.

    SUCCESS data:
      {
        "total_processes": <int>,
        "processes": [
          {
            "pid": <int>,
            "fd_count": <int>,
            "fds": [{"fd": <int>, "type": "REG|DIR|OTHER", "path": "<str>"}]
          }, ...
        ]
      }
    """
    subtype = "FILE_DESCRIPTORS"
    try:
        processes = []
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                fd_dir = f"/proc/{pid}/fd"
                if not os.path.exists(fd_dir):
                    continue

                fds = []
                for fd in os.listdir(fd_dir):
                    fd_link = os.path.join(fd_dir, fd)
                    try:
                        fd_path = os.readlink(fd_link)
                    except OSError as e:
                        # Unreadable or permission issues
                        fds.append(
                            {
                                "fd": int(fd),
                                "type": "OTHER",
                                "path": f"<unreadable: {e}>",
                            }
                        )
                        continue

                    # Classify by resolved target where feasible
                    try:
                        fd_type = (
                            "REG"
                            if os.path.isfile(fd_path)
                            else "DIR" if os.path.isdir(fd_path) else "OTHER"
                        )
                    except Exception:
                        fd_type = "OTHER"

                    fds.append({"fd": int(fd), "type": fd_type, "path": fd_path})

                processes.append({"pid": int(pid), "fd_count": len(fds), "fds": fds})
            except Exception:
                # Ignore per-process failures; continue enumerating others
                continue

        data = {"total_processes": len(processes), "processes": processes}
        return make_success_response(TaskType.STATE, subtype, data)

    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error monitoring file descriptors: {e}",
        )


def monitor_known_directories(
    known_directories_file: Optional[str] = None,
    has_input_file: bool = False,
    known_directories: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Monitor known directories in the system.

    Args:
        known_directories_file: Path to a file with newline-separated directories to monitor.
        has_input_file: If True, read directories from known_directories_file.
        known_directories: Iterable of directories used when has_input_file is False.

    SUCCESS data:
      { "directories": [ { "path": "<dir>", "contents": [<entries>|<error msg>] }, ... ] }
    """
    subtype = "KNOWN_DIRECTORIES"

    try:
        if has_input_file:
            if not known_directories_file or not os.path.isfile(known_directories_file):
                return make_error_response(
                    TaskType.STATE,
                    subtype,
                    ErrorCode.INVALID_ARGUMENTS,
                    "known_directories_file must be a valid path if has_input_file is True.",
                )
            try:
                with open(known_directories_file, "r") as f:
                    directories = [line.strip() for line in f if line.strip()]
            except Exception as e:
                return make_error_response(
                    TaskType.STATE,
                    subtype,
                    ErrorCode.IO_FAILURE,
                    f"Failed to read known_directories_file '{known_directories_file}': {e}",
                )
        else:
            if known_directories is None:
                # conservative default set, no mutable default arguments
                directories = ["/dev", "/tmp", "/sys"]
            else:
                directories = list(known_directories)

        directories_info = []
        for directory in directories:
            if os.path.exists(directory) and os.path.isdir(directory):
                try:
                    contents = os.listdir(directory)
                except Exception as e:
                    contents = [f"Error reading directory: {e}"]
                directories_info.append({"path": directory, "contents": contents})
            else:
                directories_info.append(
                    {
                        "path": directory,
                        "contents": ["Directory does not exist or is not a directory."],
                    }
                )

        data = {"directories": directories_info}
        return make_success_response(TaskType.STATE, subtype, data)

    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error monitoring known directories: {e}",
        )


def monitor_file_systems() -> Dict[str, Any]:
    """
    Monitor file systems by reading /proc/filesystems and mapping to /etc/fstab where possible.

    SUCCESS data:
      {
        "total_filesystems": <int>,
        "filesystems": [
          { "type": "<fstype>", "mount_point": "<str|None>", "options": "<str|None>" }, ...
        ]
      }
    """
    subtype = "FILE_SYSTEMS"
    try:
        filesystems = []

        # Read supported filesystems (ignoring nodev, to match your prior intent)
        supported_fs = []
        with open("/proc/filesystems", "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("nodev"):
                    # keep parity with original behavior
                    continue
                supported_fs.append(line)

        # Build a quick lookup from /etc/fstab (if present)
        fstab_entries = []
        try:
            with open("/etc/fstab", "r") as fstab:
                for fstab_line in fstab:
                    fstab_line = fstab_line.strip()
                    if not fstab_line or fstab_line.startswith("#"):
                        continue
                    parts = fstab_line.split()
                    if len(parts) >= 4:
                        # device, mount_point, fstype, options
                        fstab_entries.append(
                            {
                                "mount_point": parts[1],
                                "type": parts[2],
                                "options": parts[3],
                            }
                        )
        except Exception:
            # /etc/fstab may be restricted or absent in containerized contexts; tolerate silently
            pass

        # Map supported filesystems to fstab info (first match where types coincide)
        for fs_type in supported_fs:
            mount_point = None
            options = None
            for entry in fstab_entries:
                if entry.get("type") == fs_type:
                    mount_point = entry.get("mount_point")
                    options = entry.get("options")
                    break
            filesystems.append(
                {"type": fs_type, "mount_point": mount_point, "options": options}
            )

        data = {"total_filesystems": len(filesystems), "filesystems": filesystems}
        return make_success_response(TaskType.STATE, subtype, data)

    except FileNotFoundError as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.IO_FAILURE,
            f"Required proc file missing: {e}",
        )
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error monitoring file systems: {e}",
        )
