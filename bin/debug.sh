#!/bin/bash

# Find the project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

# Activate uv venv
source "$PROJECT_ROOT/.venv/bin/activate"

# Run python with sudo and debugpy, passing all script arguments to main.py
exec sudo env "PATH=$PATH" "VIRTUAL_ENV=$VIRTUAL_ENV" python -m debugpy --listen 5678 --wait-for-client "$PROJECT_ROOT/bin/main.py" "$@"

# Then initiate the debug process from vscode with appropriately configures launch.json