# Requirements

## Signature-based detection

To run the most basic setup for signature-based detection for linux rootkits.

First install yara using your favourite package manager:

```bash
sudo dnf install yara
```

Then, create a directory for the output logs.

```bash
mkdir -p logs/yara/
```


After creating the directory, run yara after updating submodules `git submodule update --remote` to fetch any new rules added by Elastic.

```bash
yara -r yara/yara/rules/Linux*.yar ~ > logs/yara/scan-$(date +%F_%H-%M-%S).log 2>&1
```

