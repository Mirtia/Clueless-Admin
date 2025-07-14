import argparse    

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