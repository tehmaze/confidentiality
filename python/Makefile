PYTHON ?= python3

.PHONY: all

all:

install-deps:
	$(PYTHON) -m pip install -U -r requirements.txt

install-test-deps: install-deps
	$(PYTHON) -m pip install -U -r requirements-test.txt

test:
	PYTHONPATH=. $(PYTHON) -m pytest -v
