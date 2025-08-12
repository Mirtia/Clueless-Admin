.PHONY: all format check imports

VENV_ACTIVATE = . .venv/bin/activate

all: format check imports

format:
	$(VENV_ACTIVATE) && isort src/ bin/
	$(VENV_ACTIVATE) && black src/ bin/

check:
	$(VENV_ACTIVATE) importchecker src/ bin/

imports: check

