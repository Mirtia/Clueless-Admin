.PHONY: all format check imports

VENV_ACTIVATE = . .venv/bin/activate

all: format check imports

format:
	$(VENV_ACTIVATE) && isort src/
	$(VENV_ACTIVATE) && black src/

check:
	$(VENV_ACTIVATE) importchecker src/

imports: check

