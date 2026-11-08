CARGO ?= cargo
CONFIG ?= elira.toml
IMAGE ?= elira

.PHONY: build test lint fmt run check docker

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

run:
	$(CARGO) run -p elira -- run --config $(CONFIG)

check:
	$(CARGO) run -p elira -- check --config $(CONFIG)

docker:
	docker build -t $(IMAGE) .
