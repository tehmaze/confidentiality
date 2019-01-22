IMPLEMENTATIONS ?= go javascript python ruby
ROOT            ?= $(shell pwd)

.PHONY: all

all:

install-test-deps:
	for IMPLEMENTATION in $(IMPLEMENTATIONS); do \
		echo "Installing test dependancies for $$IMPLEMENTATION"; \
		cd $(ROOT)/$$IMPLEMENTATION && $(MAKE) install-test-deps; \
	done

test: install-test-deps
	for IMPLEMENTATION in $(IMPLEMENTATIONS); do \
		cd $(ROOT)/$$IMPLEMENTATION && $(MAKE) test; \
	done
