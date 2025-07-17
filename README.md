# Requirements

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

**Warning**: Make sure that the python version defined by `uv` matches the python version of your system as uv venv creation was performed using `--system-site-packages`. 

## Running clueless admin

Examples:

```sh
```

## Debugging

First, run the script in `bin/debug.sh` providing command line arugments. The script runs the module with sudo privileges as some files require root access to be read. Run with your own responsibility.
Then, attach to `.vscode` debugger and have fun debugging.



