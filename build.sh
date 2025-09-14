#!/bin/bash
# Optimized build script for Clueless Administrator with ccache and uv optimizations

set -e

echo "Building Clueless Administrator with Nuitka"

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed. Install it with:"
    echo "curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check if ccache is available
if command -v ccache &> /dev/null; then
    echo "ccache found - builds will be faster!"
    # Don't override CC/CXX - let Nuitka handle it
    # Show ccache stats
    echo "ccache stats:"
    ccache -s | head -5
else
    echo "ccache not found. Install with: sudo apt install ccache"
fi

# Install dependencies with optimizations
echo "Installing build dependencies..."
uv sync --extra build

# Build onefile executable (simpler and faster)
echo "Building onefile executable..."
echo "This may take 5-15 minutes. Please be patient."

# Build with optimizations
uv run python -m nuitka \
    --onefile \
    --assume-yes-for-downloads \
    --output-dir=dist \
    --output-filename=clueless-admin \
    --include-package=clueless_admin \
    --no-pyi-file \
    --remove-output \
    --jobs=4 \
    --lto=yes \
    bin/main.py

if [ $? -eq 0 ]; then
    echo "Build completed successfully!"
    echo "Executable created: dist/clueless-admin"
    echo "Test it with: ./dist/clueless-admin --help"
    
    # Show ccache stats if available
    if command -v ccache &> /dev/null; then
        echo "Final ccache stats:"
        ccache -s | head -5
    fi
    
    # Show executable size
    if [ -f "dist/clueless-admin" ]; then
        SIZE=$(du -h dist/clueless-admin | cut -f1)
        echo "Executable size: ${SIZE}"
    fi
else
    echo "Build failed!"
    exit 1
fi
