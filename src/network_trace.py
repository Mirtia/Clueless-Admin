from datetime import datetime
import os
from pyroute2 import iptc
import json


def parse_proc_net(filename) -> tuple:
    """Parse the /proc/net/tcp or /proc/net/udp file to extract socket information.

    Args:
        filename (_type_): Path to the /proc/net/tcp or /proc/net/udp file.

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

    Returns:
        dict: A dictionary containing the timestamp, total number of sockets, and a list of socket details.
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

    Returns:
        dict: A dictionary containing the timestamp, total number of sockets, and a list of socket details.
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

    Returns:
        dict: A dictionary containing the timestamp, total number of sockets, and a list of socket details.
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

    Returns:
        dict: A dictionary containing the timestamp, total number of sockets, and a list of socket details.
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

    Returns:
        dict: A dictionary containing the timestamp, total number of interfaces, and a list of interface details.
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


def list_iptables_filter_table(indent=2) -> dict:
    """List all iptables rules in the filter table.

    Returns:
        dict: A JSON string containing the timestamp, a list of chains with their rules, and a message.
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
    return json.dumps(result, indent=indent)


def list_unix_sockets() -> dict:
    """List all Unix domain sockets from /proc/net/unix.

    Returns:
        dict: A dictionary containing the timestamp, total number of sockets, and a list of socket details.
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
    """List all ARP table entries from /proc/net/arp.

    Returns:
        dict: A dictionary containing the timestamp, total number of entries, and a list of ARP entries.
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
