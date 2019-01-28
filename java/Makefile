.PHONY: all

all: build test

install-build-deps:
	gradle wrapper

build: install-build-deps
	./gradlew build --refresh-dependencies
	./gradlew jar

install-test-deps: install-build-deps

test: install-test-deps
	./gradlew test

clean:
	$(RM) -r .gradle build gradle gradlew