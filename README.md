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
Lsudo chkrootkit
# Recommending expert mode:
mkdir -p ../../logs/chkrootkit/ && sudo chkrootkit -x &> ../../logs/chkrootkit/chkrootkit.logs 
```

## Volatility 

[Volatility plugins](https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/plugins/linux)
