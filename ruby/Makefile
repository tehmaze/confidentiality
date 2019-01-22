.PHONY: all

all:

install-test-deps:
	bundle install

test: install-test-deps
	PATH="$$PATH:$(shell pwd)/bin" rspec