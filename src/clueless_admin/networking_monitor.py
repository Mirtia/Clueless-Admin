import json
import os
from datetime import datetime

import iptc


def call(duration: int, frequency: int, output_dir: str = "./net_output"):
    """
    Periodically runs all network monitor functions and saves each output as:
    output_dir/net_monitor_<timestamp>/<monitor_name>_<timestamp>_<iteration>.json
    """
    os.makedirs(output_dir, exist_ok=True)
    num_calls = int(duration // frequency)
    if duration % frequency != 0:
        num_calls += 1

    root_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"net_monitor_{root_timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    start_time = time.time()
    for i in range(num_calls):
        elapsed = time.time() - start_time
        if elapsed > duration:
            break

        monitors = {
            "list_tcp6_sockets": list_tcp6_sockets(),
            "list_udp6_sockets": list_udp6_sockets(),
            "list_tcp_sockets": list_tcp_sockets(),
            "list_udp_sockets": list_udp_sockets(),
            "list_network_interfaces": list_network_interfaces(),
            "list_iptables_filter_table": list_iptables_filter_table(),
            "list_unix_sockets": list_unix_sockets(),
            "list_arp_table": list_arp_table(),
        }

        iteration = i
        for monitor_name, result in monitors.items():
            filename = f"{monitor_name}_{root_timestamp}_{iteration}.json"
            filepath = os.path.join(run_dir, filename)
            try:
                # list_iptables_filter_table might return a string
                if isinstance(result, str):
                    result = json.loads(result)
                with open(filepath, "w") as f:
                    json.dump(result, f, indent=2)
            except Exception as e:
                print(f"Failed to write {filepath}: {e}")

        # Sleep until next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def parse_proc_net(filename: str) -> tuple:
    """Parse the /proc/net/tcp or /proc/net/udp file to extract socket information.

    Args:
        filename (str): Path to the /proc/net/tcp or /proc/net/udp file.

    Returns:
        tuple: A tuple containing a list of socket dictionaries and a status message.
    """
    sockets = []
    try:
        with open(filename, "r") as f:
            lines = f.readlines()[1:]  # skip header
        for line in lines:
            cols = line.strip().split()
            if len(cols) < 10:
                continue
            local_addr, local_port = cols[1].split(":")
            remote_addr, remote_port = cols[2].split(":")
            state = cols[3]
            inode = cols[9]

            # Convert hex IP and port
            lip = ".".join(str(int(local_addr[i : i + 2], 16)) for i in (6, 4, 2, 0))
            lport = int(local_port, 16)
            rip = ".".join(str(int(remote_addr[i : i + 2], 16)) for i in (6, 4, 2, 0))
            rport = int(remote_port, 16)

            sockets.append(
                {
                    "local_ip": lip,
                    "local_port": lport,
                    "remote_ip": rip,
                    "remote_port": rport,
                    "state": state,
                    "inode": inode,
                }
            )
        return sockets, "ok"
    except Exception as e:
        return None, f"Error parsing {filename}: {e}"


def list_tcp6_sockets() -> dict:
    """List all TCP6 sockets from /proc/net/tcp6.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "protocol": "tcp6",
            "total": 10,
            "sockets": [
                {
                    "local_ip": "::1",
                    "local_port": 80,
                    "remote_ip": "::",
                    "remote_port": 0,
                    "state": "01",
                    "inode": "12345"
                },
                ...
            ]
        },
        "message": "TCP6 sockets listed successfully."
    }
    """
    sockets, msg = parse_proc_net("/proc/net/tcp6")
    if sockets is None:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": msg,
        }
    return {
        "timestamp": datetime.now().isoformat(),
        "data": {
            "protocol": "tcp6",
            "total": len(sockets),
            "sockets": sockets,
        },
        "message": "TCP6 sockets listed successfully.",
    }


def list_udp6_sockets() -> dict:
    """List all UDP6 sockets from /proc/net/udp6.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "protocol": "udp6",
            "total": 10,
            "sockets": [
                {
                    "local_ip": "::1",
                    "local_port": 53,
                    "remote_ip": "::",
                    "remote_port": 0,
                    "inode": "12345"
                },
                ...
            ]
        },
        "message": "UDP6 sockets listed successfully."
    }
    """
    sockets, msg = parse_proc_net("/proc/net/udp6")
    if sockets is None:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": msg,
        }
    return {
        "timestamp": datetime.now().isoformat(),
        "data": {
            "protocol": "udp6",
            "total": len(sockets),
            "sockets": sockets,
        },
        "message": "UDP6 sockets listed successfully.",
    }


def list_tcp_sockets() -> dict:
    """List all TCP sockets from /proc/net/tcp.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "protocol": "tcp",
            "total": 10,
            "sockets": []
        },
        "message": "TCP sockets listed successfully."
    }
    """
    sockets, msg = parse_proc_net("/proc/net/tcp")
    if sockets is None:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": msg,
        }
    return {
        "timestamp": datetime.now().isoformat(),
        "data": {
            "protocol": "tcp",
            "total": len(sockets),
            "sockets": sockets,
        },
        "message": "TCP sockets listed successfully.",
    }


def list_udp_sockets() -> dict:
    """List all UDP sockets from /proc/net/udp.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "protocol": "udp",
            "total": 10,
            "sockets": []
        },
        "message": "UDP sockets listed successfully."
    }
    """
    sockets, msg = parse_proc_net("/proc/net/udp")
    if sockets is None:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": msg,
        }
    return {
        "timestamp": datetime.now().isoformat(),
        "data": {
            "protocol": "udp",
            "total": len(sockets),
            "sockets": sockets,
        },
        "message": "UDP sockets listed successfully.",
    }


def list_network_interfaces() -> dict:
    """List all network interfaces and their statistics from /sys/class/net/.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total_interfaces": 5,
            "interfaces": [
                {
                    "name": "eth0",
                    "rx_bytes": 12345678,
                    "tx_bytes": 87654321
                },
                ...
            ]
        },
        "message": "Network interfaces listed successfully."
    }
    """
    interfaces = []
    try:
        for iface in os.listdir("/sys/class/net/"):
            iface_path = os.path.join("/sys/class/net/", iface)
            if not os.path.isdir(iface_path):
                continue
            # Try to get some stats
            stats_path = os.path.join(iface_path, "statistics")
            rx_bytes = tx_bytes = None
            if os.path.isdir(stats_path):
                try:
                    with open(os.path.join(stats_path, "rx_bytes")) as f:
                        rx_bytes = int(f.read().strip())
                    with open(os.path.join(stats_path, "tx_bytes")) as f:
                        tx_bytes = int(f.read().strip())
                except Exception:
                    pass
            interfaces.append(
                {
                    "name": iface,
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                }
            )
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {
                "total_interfaces": len(interfaces),
                "interfaces": interfaces,
            },
            "message": "Network interfaces listed successfully.",
        }
    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error reading /sys/class/net: {e}",
        }


def list_iptables_filter_table() -> dict:
    """List all iptables rules in the filter table.

    Returns a JSON with the following structure:
    {
        "timestamp": "<ISO8601_TIMESTAMP>",
        "data": {
            "chains": [
                {
                    "name": "<CHAIN_NAME>",
                    "policy": "<CHAIN_POLICY or null>",
                    "rules": [
                        {
                            "src": "<SOURCE_CIDR>",
                            "dst": "<DESTINATION_CIDR>",
                            "protocol": "<PROTOCOL>",
                            "in_interface": "<IN_INTERFACE>",
                            "out_interface": "<OUT_INTERFACE>",
                            "target": "<TARGET_NAME or null>",
                            "matches": [
                                "<MATCH1_NAME>",
                                "<MATCH2_NAME>",
                                ...
                            ]
                        },
                        ...
                    ]
                },
                ...
            ]
        },
        "message": "<STATUS_MESSAGE>"
    }
    """
    # It requires root privileges to access iptables rules.
    if os.geteuid() != 0:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": "Error: This function requires root privileges.",
        }

    result = {
        "timestamp": datetime.now().isoformat(),
        "data": {"chains": []},
        "message": "",
    }
    try:
        table = iptc.Table(iptc.Table.FILTER)
        table.refresh()
        for chain in table.chains:
            chain_data = {
                "name": chain.name,
                "policy": chain.get_policy() if chain.is_builtin() else None,
                "rules": [],
            }
            for rule in chain.rules:
                rule_dict = {
                    "src": rule.src,
                    "dst": rule.dst,
                    "protocol": rule.protocol,
                    "in_interface": rule.in_interface,
                    "out_interface": rule.out_interface,
                    "target": rule.target.name if rule.target else None,
                    "matches": [match.name for match in rule.matches],
                }
                chain_data["rules"].append(rule_dict)
            result["data"]["chains"].append(chain_data)
        result["message"] = "Filter table iptables rules retrieved successfully."
    except Exception as e:
        result["message"] = f"Error: {e}"
    return json.dumps(result, indent=2)


def list_unix_sockets() -> dict:
    """List all Unix domain sockets from /proc/net/unix.

    Returns a JSON with the following structure:
    {
        "timestamp": "2025-10-01T12:00:00",
        "data": {
            "total": 10,
            "sockets": [
                {
                    "num": "12345",
                    "ref_count": "1",
                    "protocol": "00000000",
                    "flags": "0x0",
                    "type": "DGRAM",
                    "state": "01",
                    "path": "/var/run/socket"
                },
                ...
            ]
        },
        "message": "Unix sockets listed successfully."
    }
    """
    try:
        with open("/proc/net/unix", "r") as f:
            lines = f.readlines()[1:]
        sockets = []
        for line in lines:
            fields = line.strip().split()
            path = fields[6] if len(fields) > 6 else None
            sockets.append(
                {
                    "num": fields[0],
                    "ref_count": fields[1],
                    "protocol": fields[2],
                    "flags": fields[3],
                    "type": fields[4],
                    "state": fields[5],
                    "path": path,
                }
            )
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {
                "total": len(sockets),
                "sockets": sockets,
            },
            "message": "Unix sockets listed successfully.",
        }
    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error reading /proc/net/unix: {e}",
        }


def list_arp_table() -> dict:
    """Lists all entries from the ARP table as found in /proc/net/arp and returns them in a structured JSON format.

    Returns:
        dict: A dictionary with the following structure:
            {
                "timestamp": "<ISO8601_TIMESTAMP>",
                "data": {
                    "total": <INTEGER_TOTAL_ENTRIES>,
                    "arp_entries": [
                        {
                            "ip_address": "<IPV4_ADDRESS>",
                            "hw_type": "<HARDWARE_TYPE_CODE>",
                            "flags": "<ARP_FLAGS>",
                            "mac_address": "<MAC_ADDRESS>",
                            "mask": "<SUBNET_MASK>",
                            "device": "<INTERFACE_NAME>"
                        },
                        ...
                    ]
                },
                "message": "<STATUS_MESSAGE>"
            }
    """
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
        entries = []
        for line in lines:
            fields = line.strip().split()
            entries.append(
                {
                    "ip_address": fields[0],
                    "hw_type": fields[1],
                    "flags": fields[2],
                    "mac_address": fields[3],
                    "mask": fields[4],
                    "device": fields[5],
                }
            )
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {"total": len(entries), "arp_entries": entries},
            "message": "ARP table entries listed successfully.",
        }
    except Exception as e:
        return {
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "message": f"Error reading /proc/net/arp: {e}",
        }
