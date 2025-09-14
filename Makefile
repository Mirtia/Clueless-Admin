.PHONY: all format check imports build clean clean-cache

# Use uv instead of venv
UV = uv

all: format check imports

format:
	$(UV) run isort src/ bin/
	$(UV) run black src/ bin/

check:
	$(UV) run importchecker src/ bin/

imports: check

# Build targets
install-deps:
	$(UV) sync --extra build

build: install-deps
	./build.sh

clean:
	rm -rf dist/ build/

clean-cache:
	ccache -C
	$(UV) cache clean
