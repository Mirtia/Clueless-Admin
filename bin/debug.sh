#!/bin/bash

# Find the project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

# Activate uv virtualenv
source "$PROJECT_ROOT/.venv/bin/activate"

# Run python with sudo and debugpy
exec sudo env "PATH=$PATH" "VIRTUAL_ENV=$VIRTUAL_ENV" python -m debugpy --listen 5678 --wait-for-client "$PROJECT_ROOT/bin/main.py" --ebpf