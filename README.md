# Clueless Admin

## Usage

> `ebpf`, `io_uring` and `network` (iptables) monitoring require `sudo`.

```sh

     _____ _            _                  ___      _           _
    /  __ \ |          | |                / _ \    | |         (_)
    | /  \/ |_   _  ___| | ___  ___ ___  / /_\ \ __| |_ __ ___  _ _ __
    | |   | | | | |/ _ \ |/ _ \/ __/ __| |  _  |/ _` | '_ ` _ \| | '_ \
    | \__/\ | |_| |  __/ |  __/\__ \__ \ | | | | (_| | | | | | | | | | |
     \____/_|\__,_|\___|_|\___||___/___/ \_| |_/\__,_|_| |_| |_|_|_| |_|
    
usage: main.py [-h] [--duration DURATION] [--frequency FREQUENCY] [--output-dir OUTPUT_DIR] [--ebpf] [--bcc-enabled] [--ftrace] [--max-trace-lines] [--io-uring] [--max-events] [--timeout] [--networking] [--process] [--file-system] [--known-directories] [--modules] [--syscall-monitor] [--kallsyms]

Clueless Admin monitoring tool.

options:
  -h, --help            show this help message and exit
  --duration DURATION   Duration in seconds for each monitoring task (default: 60 seconds)
  --frequency FREQUENCY
                        Frequency in seconds to run each monitoring task (default: 1 second)
  --output-dir OUTPUT_DIR
                        The output directory of the generated JSON monitoring responses.
  --ebpf                [sudo] Enable eBPF monitoring.
  --bcc-enabled         Use BCC for enabled eBPF monitoring.
  --ftrace              Enable ftrace monitoring.
  --max-trace-lines     Maximum lines to include from trace file.
  --io-uring            [sudo] Enable io_uring monitoring.
  --max-events          Maximum events to monitor for io_uring.
  --timeout             Timeout io_uring monitoring after provided seconds.
  --networking          [sudo] Enable networking monitoring.
  --process             Enable process monitoring.
  --file-system         Enable file system monitoring.
  --known-directories   Provide a file (.txt file with one column) with directories to monitor.
  --modules             Enable kernel modules monitoring.
  --syscall-monitor     [sudo] Enable syscall monitoring (not implemented).
  --kallsyms            [sudo] Enable kallsyms monitoring.
```

### Debugging

First, run the script in `bin/debug.sh` providing command line arugments. The script runs the module with sudo privileges as some files require root access to be read. Run with your own responsibility.
Open `code` as root with the following command:
```sh
sudo codium . --no-sandbox --user-data-dir <USER_DIRECTORY>
```
Then, attach to `.vscode` debugger and have fun debugging.

### Tests

To run the tests, from the root directory, execute the following: 
```sh
sudo PYTHONPATH=src .venv/bin/python -m pytest -rs
```


## Signature-based detection

To run the most basic setup for signature-based detection for linux rootkits.

First install *yara* using your favourite package manager:

```bash
sudo dnf install yara
```

Then, create a directory for the output logs:

```bash
mkdir -p logs/yara/
```

After creating the directory, update submodules by running `git submodule update --remote` to fetch any new rules added by Elastic and then run the following:

```bash
yara -r yara/yara/rules/Linux*.yar ~ > logs/yara/scan-$(date +%F_%H-%M-%S).log 2>&1
```


## Tools

### Chkrootkit

To use [chkrootkit](tools/chkrootkit/), build it with `make`. It requires `glibc-static`.

To run:
```bash
sudo chkrootkit
# Recommending expert mode:
mkdir -p ../../logs/chkrootkit/ && sudo chkrootkit -x &> ../../logs/chkrootkit/chkrootkit.logs 
```


## Volatility 

[Volatility plugins](https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/plugins/linux)


## Additional required packages

For ebpf monitoring with bcc, the following system packages are required:

```sh
sudo dnf install bcc bcc-devel python3-bcc 
```

For monitoring with `bpftool`:

```sh
sudo dnf install bpftool
``` 

For tests:
```sh
sudo dnf install bpftrace
```

And also:
```
git clone https://github.com/axboe/liburing.git
cd liburing
configure
make
cp examples/io_uring-cp /usr/bin
```

**Warning**: Make sure that the python version defined by `uv` matches the python version of your system as uv venv creation was performed using `--system-site-packages`. 

