import argparse
import asyncio
from ebpf_monitor import *
from file_system_monitor import *
from ftrace_monitor import *
from io_uring_monitor import *
from modules_monitor import *
from networking_monitor import *
from process_monitor import *
from syscall_table_monitor import *

def get_args(): 
  parser = argparse.ArgumentParser(description="Clueless Admin monitoring tool.")
  parser.add_argument(
      "--duration",
      type=int,
      default=60,
      help="Duration in seconds for each monitoring task (default: 60 seconds)",
  )
  parser.add_argument(
      "--frequency",
      type=int,
      default=1,
      help="Frequency in seconds to run each monitoring task (default: 1 second)",
  )
  parser.add_argument(
      "--use_bcc",
      action="store_true",
      help="Use BCC for eBPF monitoring (default: False)",
  )
  parser.add_argument(
      "--use_ftrace",
      action="store_true",
      help="Use ftrace for monitoring (default: False)",
  )
  parser.add_argument(
      "--use_io_uring",
      action="store_true",
      help="Use io_uring for monitoring (default: False)",
  )
  parser.add_argument(
      "--use_syscall_timing",
      action="store_true",
      help="Enable syscall timing checks (default: False)",
  )
  parser.add_argument(
      "--use_networking",
      action="store_true",
      help="Enable networking monitoring (default: False)",
  )
  parser.add_argument(
      "--use_process_monitor",
      action="store_true",
      help="Enable process monitoring (default: False)",
  )
  parser.add_argument(
      "--use_file_system",
      action="store_true",
      help="Enable file system monitoring (default: False)",
  )
  parser.add_argument(
      "--use_modules",
      action="store_true",
      help="Enable kernel modules monitoring (default: False)",
  )
  args = parser.parse_args()
  return args


def main():
    print(
        " _____ _            _                  ___      _           _       "
        "/  __ \ |          | |                / _ \    | |         (_)      "
        "| /  \/ |_   _  ___| | ___  ___ ___  / /_\ \ __| |_ __ ___  _ _ __  "
        "| |   | | | | |/ _ \ |/ _ \/ __/ __| |  _  |/ _` | '_ ` _ \| | '_ \ "
        "| \__/\ | |_| |  __/ |  __/\__ \__ \ | | | | (_| | | | | | | | | | |"
        " \____/_|\__,_|\___|_|\___||___/___/ \_| |_/\__,_|_| |_| |_|_|_| |_|"
    )
    args = get_args()
    
    dispatcher = {
        "use_bcc": lambda: ebpf_monitor.call(duration=args.duration, frequency=args.frequency),
        "use_ftrace": lambda: ftrace_monitor.call(duration=args.duration, frequency=args.frequency),
        "use_io_uring": lambda: io_uring_monitor.call(duration=args.duration, frequency=args.frequency),
        "use_syscall_timing": lambda: syscall_table_monitor.call(duration=args.duration, frequency=args.frequency),
        "use_networking": lambda: networking_monitor.call(duration=args.duration, frequency=args.frequency),
        "use_process_monitor": lambda: process_monitor.call(duration=args.duration, frequency=args.frequency),
        "use_file_system": lambda: file_system_monitor.call(duration=args.duration, frequency=args.frequency),
        "use_modules": lambda: modules_monitor.call(duration=args.duration, frequency=args.frequency),
    }

    tasks = []
    for arg, func in dispatcher.items():
        if getattr(args, arg, False):
            print(f"Starting {arg.replace('use_', '').replace('_', ' ').title()} Monitor asynchronously...")
            tasks.append(asyncio.create_task(func()))

    await asyncio.gather(*tasks)