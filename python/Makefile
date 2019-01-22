PYTHON ?= python3

.PHONY: all

all:

install-deps:
	$(PYTHON) -m pip install -r requirements.txt

install-test-deps: install-deps
	$(PYTHON) -m pip install -r requirements-test.txt

test:
	PYTHONPATH=. $(PYTHON) -m pytest -v
