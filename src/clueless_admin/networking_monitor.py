# net_monitor.py
import json
import os
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import iptc

from clueless_admin.response import (
    TaskType,
    ErrorCode,
    make_success_response,
    make_error_response,
)


async def call(duration: int, frequency: int, output_dir: str = "data/output"):
    """
    Periodically runs all network monitor functions and saves each output as:
      output_dir/net_monitor_<timestamp>/<monitor_name>_<timestamp>_<iteration>.json
    """
    # Validate inputs
    if frequency <= 0:
        err = make_error_response(
            TaskType.STATE,
            "NET_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid frequency: {frequency} (must be > 0)",
        )
        raise ValueError(json.dumps(err))
    if duration <= 0:
        err = make_error_response(
            TaskType.STATE,
            "NET_MONITOR_CALL",
            ErrorCode.INVALID_ARGUMENTS,
            f"Invalid duration: {duration} (must be > 0)",
        )
        raise ValueError(json.dumps(err))

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

        monitors: Dict[str, Dict[str, Any]] = {
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
                # Persist exactly the schema object
                with open(filepath, "w") as f:
                    json.dump(result, f, indent=2, default=str)
            except Exception as e:
                io_err = make_error_response(
                    TaskType.STATE,
                    "NET_MONITOR_WRITE",
                    ErrorCode.IO_FAILURE,
                    f"Failed to write {filepath}: {e}",
                )
                # Best-effort: emit to stdout to avoid silent loss
                print(json.dumps(io_err))

        # Sleep until next scheduled time
        time_to_next = frequency - ((time.time() - start_time) % frequency)
        if time_to_next > 0:
            time.sleep(min(time_to_next, max(0, duration - (time.time() - start_time))))


def _hex_to_ipv4(hexip: str) -> str:
    # hexip like "0100007F" (little-endian)
    octets = [str(int(hexip[i : i + 2], 16)) for i in (6, 4, 2, 0)]
    return ".".join(octets)


def _hex_to_ipv6(hexip: str) -> str:
    # hexip is 32 hex chars, little-endian groups of 4 bytes reversed to big-endian IPv6
    # /proc/net/tcp6 stores address as 32 hex chars in network-byte-order but grouped little-endian per 32-bit chunk.
    # The canonical approach is to reverse each 4-byte (8 hex) chunk order of bytes, then join.
    # Example transformation adapted for correctness without external libs.
    if len(hexip) != 32:
        return "::"
    # Convert to bytes in little-endian 32-bit chunks, then to network order
    chunks = [hexip[i : i + 8] for i in range(0, 32, 8)]
    # For each 8-hex chunk, reverse byte-pairs
    bytes_be: List[str] = []
    for ch in chunks:
        bytes_le = [ch[j : j + 2] for j in range(0, 8, 2)]
        bytes_be.extend(bytes_le[::-1])
    # Now we have 16 bytes in big-endian order
    groups = ["".join(bytes_be[i : i + 2]) for i in range(0, 16, 2)]
    # Compress leading zeros when formatting
    hextets = [format(int(g, 16), "x") for g in groups]
    # Collapse consecutive zero groups (::) minimally (single run)
    # Simple implementation: find longest zero run
    zero_runs: List[Tuple[int, int]] = []
    start = None
    for idx, val in enumerate(hextets):
        if val == "0":
            if start is None:
                start = idx
        else:
            if start is not None:
                zero_runs.append((start, idx - 1))
                start = None
    if start is not None:
        zero_runs.append((start, len(hextets) - 1))
    if zero_runs:
        # choose the longest run
        best = max(zero_runs, key=lambda ab: ab[1] - ab[0])
        a, b = best
        # replace run with empty and mark with ''
        collapsed = hextets[:a] + [""] + hextets[b + 1 :]
        # ensure no leading/trailing extra colons
        addr = ":".join(collapsed)
        if addr.startswith(":"):
            addr = ":" + addr
        if addr.endswith(":"):
            addr = addr + ":"
        # fix potential ':::' occurrences
        while ":::" in addr:
            addr = addr.replace(":::", "::")
        if addr == "":
            addr = "::"
        return addr
    return ":".join(hextets)


def _tcp_udp_state_hex(state_hex: str) -> str:
    # Keep raw hex string from /proc; caller can map if needed
    return state_hex


def _parse_proc_net_v4(path: str) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    """
    Parse /proc/net/{tcp,udp} (IPv4).
    Returns (sockets | None, message)
    """
    sockets: List[Dict[str, Any]] = []
    try:
        with open(path, "r") as f:
            lines = f.readlines()[1:]  # skip header
        for line in lines:
            cols = line.strip().split()
            if len(cols) < 10:
                continue
            local_addr, local_port = cols[1].split(":")
            remote_addr, remote_port = cols[2].split(":")
            state = _tcp_udp_state_hex(cols[3])
            inode = cols[9]

            lip = _hex_to_ipv4(local_addr)
            lport = int(local_port, 16)
            rip = _hex_to_ipv4(remote_addr)
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
        return None, f"Error parsing {path}: {e}"


def _parse_proc_net_v6(path: str) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    """
    Parse /proc/net/{tcp6,udp6} (IPv6).
    Returns (sockets | None, message)
    """
    sockets: List[Dict[str, Any]] = []
    try:
        with open(path, "r") as f:
            lines = f.readlines()[1:]  # skip header
        for line in lines:
            cols = line.strip().split()
            if len(cols) < 10:
                continue
            local_addr, local_port = cols[1].split(":")
            remote_addr, remote_port = cols[2].split(":")
            state = _tcp_udp_state_hex(cols[3])
            inode = cols[9]

            lip = _hex_to_ipv6(local_addr)
            lport = int(local_port, 16)
            rip = _hex_to_ipv6(remote_addr)
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
        return None, f"Error parsing {path}: {e}"


def list_tcp6_sockets() -> Dict[str, Any]:
    subtype = "TCP_SOCKETS_V6"
    sockets, msg = _parse_proc_net_v6("/proc/net/tcp6")
    if sockets is None:
        return make_error_response(
            TaskType.STATE, subtype, ErrorCode.EXECUTION_FAILURE, msg
        )
    data = {"protocol": "tcp6", "total": len(sockets), "sockets": sockets}
    return make_success_response(TaskType.STATE, subtype, data)


def list_udp6_sockets() -> Dict[str, Any]:
    subtype = "UDP_SOCKETS_V6"
    sockets, msg = _parse_proc_net_v6("/proc/net/udp6")
    if sockets is None:
        return make_error_response(
            TaskType.STATE, subtype, ErrorCode.EXECUTION_FAILURE, msg
        )
    data = {"protocol": "udp6", "total": len(sockets), "sockets": sockets}
    return make_success_response(TaskType.STATE, subtype, data)


def list_tcp_sockets() -> Dict[str, Any]:
    subtype = "TCP_SOCKETS_V4"
    sockets, msg = _parse_proc_net_v4("/proc/net/tcp")
    if sockets is None:
        return make_error_response(
            TaskType.STATE, subtype, ErrorCode.EXECUTION_FAILURE, msg
        )
    data = {"protocol": "tcp", "total": len(sockets), "sockets": sockets}
    return make_success_response(TaskType.STATE, subtype, data)


def list_udp_sockets() -> Dict[str, Any]:
    subtype = "UDP_SOCKETS_V4"
    sockets, msg = _parse_proc_net_v4("/proc/net/udp")
    if sockets is None:
        return make_error_response(
            TaskType.STATE, subtype, ErrorCode.EXECUTION_FAILURE, msg
        )
    data = {"protocol": "udp", "total": len(sockets), "sockets": sockets}
    return make_success_response(TaskType.STATE, subtype, data)


def list_network_interfaces() -> Dict[str, Any]:
    """
    Enumerate interfaces under /sys/class/net and basic RX/TX counters.
    """
    subtype = "NETWORK_INTERFACES"
    interfaces: List[Dict[str, Any]] = []
    try:
        for iface in os.listdir("/sys/class/net/"):
            iface_path = os.path.join("/sys/class/net/", iface)
            if not os.path.isdir(iface_path):
                continue
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
        data = {"total_interfaces": len(interfaces), "interfaces": interfaces}
        return make_success_response(TaskType.STATE, subtype, data)
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error reading /sys/class/net: {e}",
        )


def list_iptables_filter_table() -> Dict[str, Any]:
    """
    Enumerate iptables filter table rules (requires root).
    """
    subtype = "IPTABLES_FILTER"
    # Root requirement
    try:
        if os.geteuid() != 0:
            return make_error_response(
                TaskType.STATE,
                subtype,
                ErrorCode.EXECUTION_FAILURE,
                "This function requires root privileges.",
            )
    except AttributeError:
        # Systems without geteuid (non-POSIX); attempt and catch below
        pass

    try:
        table = iptc.Table(iptc.Table.FILTER)
        table.refresh()

        def serialize_policy(policy: Optional[iptc.Policy]) -> Optional[str]:
            if policy is None:
                return None
            if isinstance(policy, str):  # defensive
                return policy
            if hasattr(policy, "name"):
                return policy.name
            return str(policy)

        chains_out: List[Dict[str, Any]] = []
        for chain in table.chains:
            chain_data = {
                "name": chain.name,
                "policy": (
                    serialize_policy(chain.get_policy()) if chain.is_builtin() else None
                ),
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
                    "matches": [m.name for m in rule.matches],
                }
                chain_data["rules"].append(rule_dict)
            chains_out.append(chain_data)

        data = {"chains": chains_out}
        return make_success_response(TaskType.STATE, subtype, data)

    except Exception as e:
        return make_error_response(
            TaskType.STATE, subtype, ErrorCode.EXECUTION_FAILURE, f"iptables error: {e}"
        )


def list_unix_sockets() -> Dict[str, Any]:
    subtype = "UNIX_SOCKETS"
    try:
        with open("/proc/net/unix", "r") as f:
            lines = f.readlines()[1:]
        sockets: List[Dict[str, Any]] = []
        for line in lines:
            fields = line.strip().split()
            # /proc/net/unix columns:
            # Num, RefCount, Protocol, Flags, Type, State, Inode, [Path]
            entry = {
                "num": fields[0] if len(fields) > 0 else None,
                "ref_count": fields[1] if len(fields) > 1 else None,
                "protocol": fields[2] if len(fields) > 2 else None,
                "flags": fields[3] if len(fields) > 3 else None,
                "type": fields[4] if len(fields) > 4 else None,
                "state": fields[5] if len(fields) > 5 else None,
                "inode": fields[6] if len(fields) > 6 else None,
                "path": fields[7] if len(fields) > 7 else None,
            }
            sockets.append(entry)
        data = {"total": len(sockets), "sockets": sockets}
        return make_success_response(TaskType.STATE, subtype, data)
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error reading /proc/net/unix: {e}",
        )


def list_arp_table() -> Dict[str, Any]:
    subtype = "ARP_TABLE"
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
        entries: List[Dict[str, Any]] = []
        for line in lines:
            fields = line.strip().split()
            if len(fields) < 6:
                continue
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
        data = {"total": len(entries), "arp_entries": entries}
        return make_success_response(TaskType.STATE, subtype, data)
    except Exception as e:
        return make_error_response(
            TaskType.STATE,
            subtype,
            ErrorCode.EXECUTION_FAILURE,
            f"Error reading /proc/net/arp: {e}",
        )
