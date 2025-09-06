import argparse
import asyncio
import os
import sys

# Add src/ to path for imports
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

import clueless_admin.ebpf_monitor as ebpf_monitor
import clueless_admin.file_system_monitor as file_system_monitor
import clueless_admin.ftrace_monitor as ftrace_monitor
import clueless_admin.io_uring_monitor as io_uring_monitor
import clueless_admin.kallsyms_monitor as kallsyms_monitor
import clueless_admin.modules_monitor as modules_monitor
import clueless_admin.networking_monitor as networking_monitor
import clueless_admin.process_monitor as process_monitor


def get_args():
    parser = argparse.ArgumentParser(description="Clueless Admin monitoring tool.")
    # Generic arguments
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Duration in seconds for each monitoring task (default: 60 seconds)",
    )
    parser.add_argument(
        "--frequency",
        type=int,
        default=1,
        help="Frequency in seconds to run each monitoring task (default: 1 second)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/output",
        help="The output directory of the generated JSON monitoring responses.",
    )
    # Flag arguments (which monitoring methods are enabled) + method specific arguments (secondary)
    # The module specific arguments are optional, they have default values set.
    parser.add_argument(
        "--ebpf",
        action="store_true",
        help="[sudo] Enable eBPF monitoring.",
    )
    # Module specific
    parser.add_argument(
        "--bcc-enabled",
        action="store_true",
        help="Use BCC for enabled eBPF monitoring.",
    )

    parser.add_argument(
        "--ftrace",
        action="store_true",
        help="Enable ftrace monitoring.",
    )
    # Module specific
    parser.add_argument(
        "--max-trace-lines",
        action="store_true",
        help="Maximum lines to include from trace file.",
    )

    parser.add_argument(
        "--io-uring",
        action="store_true",
        help="[sudo] Enable io_uring monitoring.",
    )
    # Module specific
    parser.add_argument(
        "--max-events",
        action="store_true",
        help="Maximum events to monitor for io_uring.",
    )
    parser.add_argument(
        "--timeout",
        action="store_true",
        help="Timeout io_uring monitoring after provided seconds.",
    )

    parser.add_argument(
        "--networking",
        action="store_true",
        help="[sudo] Enable networking monitoring.",
    )

    parser.add_argument(
        "--process",
        action="store_true",
        help="Enable process monitoring.",
    )

    parser.add_argument(
        "--file-system",
        action="store_true",
        help="Enable file system monitoring.",
    )
    # Module specific
    parser.add_argument(
        "--known-directories",
        action="store_true",
        help="Provide a file (.txt file with one column) with directories to monitor.",
    )

    parser.add_argument(
        "--modules",
        action="store_true",
        help="Enable kernel modules monitoring.",
    )
    
    parser.add_argument(
        "--kallsyms",
        action="store_true",
        help="[sudo] Enable kallsyms monitoring.",
    )

    args = parser.parse_args()
    return args


async def main():
    print(
        r"""
     _____ _            _                  ___      _           _
    /  __ \ |          | |                / _ \    | |         (_)
    | /  \/ |_   _  ___| | ___  ___ ___  / /_\ \ __| |_ __ ___  _ _ __
    | |   | | | | |/ _ \ |/ _ \/ __/ __| |  _  |/ _` | '_ ` _ \| | '_ \
    | \__/\ | |_| |  __/ |  __/\__ \__ \ | | | | (_| | | | | | | | | | |
     \____/_|\__,_|\___|_|\___||___/___/ \_| |_/\__,_|_| |_| |_|_|_| |_|
    """
    )

    args = get_args()
    # TODO: Add logger
    dispatcher = {
        "ebpf": lambda: ebpf_monitor.call(
            bcc_enabled=args.bcc_enabled,
            duration=args.duration,
            frequency=args.frequency,
            output_dir=args.output_dir,
        ),
        "ftrace": lambda: ftrace_monitor.call(
            max_trace_lines=args.max_trace_lines,
            duration=args.duration,
            frequency=args.frequency,
            output_dir=args.output_dir,
        ),
        "io_uring": lambda: io_uring_monitor.call(
            duration=args.duration,
            frequency=args.frequency,
            max_events=args.max_events,
            timeout=args.timeout,
            output_dir=args.output_dir,
        ),
        "networking": lambda: networking_monitor.call(
            duration=args.duration, output_dir=args.output_dir, frequency=args.frequency
        ),
        "process": lambda: process_monitor.call(
            duration=args.duration, frequency=args.frequency, output_dir=args.output_dir
        ),
        "file_system": lambda: file_system_monitor.call(
            duration=args.duration,
            frequency=args.frequency,
            known_directories_file=(
                args.known_directories if args.known_directories else None
            ),
            output_dir=args.output_dir,
        ),
        "modules": lambda: modules_monitor.call(
            duration=args.duration, frequency=args.frequency, output_dir=args.output_dir
        ),
        "kallsyms": lambda: kallsyms_monitor.call(
            duration=args.duration,
            frequency=args.frequency,
            output_dir=args.output_dir,
        ),
    }
    tasks = []
    for arg, func in dispatcher.items():
        if getattr(args, arg, False):
            print(
                f"Starting {arg.replace('use_', '').replace('_', ' ').title()} Monitor asynchronously..."
            )
            tasks.append(asyncio.create_task(func()))

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
