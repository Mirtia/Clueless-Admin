#!/bin/bash

# Fix permissions of the output data that was generated using `sudo` when running clueless admin.
set -e

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <target_user> <target_group> <directory_or_file>"
    exit 1
fi

TARGET_USER="$1"
TARGET_GROUP="$2"
TARGET_PATH="$3"

if [[ ! -e "$TARGET_PATH" ]]; then
    echo "Error: Target path '$TARGET_PATH' does not exist."
    exit 2
fi

echo "Changing ownership of '$TARGET_PATH' to ${TARGET_USER}:${TARGET_GROUP}..."
sudo chown -R "${TARGET_USER}:${TARGET_GROUP}" "$TARGET_PATH"

echo "Ownership change for ${$TARGET_PATH} completed successfully."