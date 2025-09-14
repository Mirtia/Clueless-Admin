#!/bin/bash
# Optimized build script for Clueless Administrator with ccache and uv optimizations

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Building Clueless Administrator with Nuitka${NC}"

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo -e "${RED}Error: uv is not installed. Install it with:${NC}"
    echo "curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check if ccache is available
if command -v ccache &> /dev/null; then
    echo -e "${GREEN}✅ ccache found - builds will be faster!${NC}"
    # Don't override CC/CXX - let Nuitka handle it
    # Show ccache stats
    echo -e "${BLUE}ccache stats:${NC}"
    ccache -s | head -5
else
    echo -e "${YELLOW}⚠️  ccache not found. Install with: sudo apt install ccache${NC}"
fi

# Install dependencies with optimizations
echo -e "${YELLOW}Installing build dependencies...${NC}"
uv sync --extra build

# Build onefile executable (simpler and faster)
echo -e "${YELLOW}Building onefile executable...${NC}"
echo -e "${BLUE}This may take 5-15 minutes. Please be patient.${NC}"

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
    echo -e "${GREEN}✅ Build completed successfully!${NC}"
    echo -e "${BLUE}Executable created: dist/clueless-admin${NC}"
    echo -e "${BLUE}Test it with: ./dist/clueless-admin --help${NC}"
    
    # Show ccache stats if available
    if command -v ccache &> /dev/null; then
        echo -e "${BLUE}Final ccache stats:${NC}"
        ccache -s | head -5
    fi
    
    # Show executable size
    if [ -f "dist/clueless-admin" ]; then
        SIZE=$(du -h dist/clueless-admin | cut -f1)
        echo -e "${BLUE}Executable size: ${SIZE}${NC}"
    fi
else
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi
