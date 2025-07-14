import os
from datetime import datetime

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


def monitor_inodes():
    """
    Monitor inodes in the system.

    Reads the /proc filesystem to gather information about inodes and their usage.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_inodes": 1000,
            "inodes": [
                {
                    "inode": 123456,
                    "path": "/path/to/file",
                    "type": "REG",
                    "size": 2048
                },
                ...
            ]
        },
        "message": "Inodes monitored successfully."
    }
    """
    try:
        inodes = []
        for root, dirs, files in os.walk("/"):
            for name in files + dirs:
                path = os.path.join(root, name)
                try:
                    stat_info = os.stat(path)
                    inodes.append(
                        {
                            "inode": stat_info.st_ino,
                            "path": path,
                            "type": "REG" if os.path.isfile(path) else "DIR",
                            "size": stat_info.st_size,
                        }
                    )
                except Exception:
                    continue

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"total_inodes": len(inodes), "inodes": inodes},
            "message": "Inodes monitored successfully.",
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error monitoring inodes: {str(e)}",
        }


def monitor_known_directories(directories: list = {"/etc", "/sys", "/tmp"}):
    """
    Monitor known directories in the system.

    Reads the specified directories to gather information about their contents.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "directories": [
                {
                    "path": "/etc",
                    "contents": ["file1.conf", "file2.conf", ...]
                },
                ...
            ]
        },
        "message": "Known directories monitored successfully."
    }
    """
    try:
        directories_info = []
        for directory in directories:
            if os.path.exists(directory):
                contents = os.listdir(directory)
                directories_info.append({"path": directory, "contents": contents})

        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"directories": directories_info},
            "message": "Known directories monitored successfully.",
        }

    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
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
