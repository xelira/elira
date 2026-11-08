CARGO ?= cargo
CONFIG ?= elira.toml
IMAGE ?= elira
URL ?= http://127.0.0.1:8080/
FUZZ_TARGET ?= config
FUZZ_TIME ?= 60

.PHONY: build fmt lint test check config-check audit deny fuzz load bench run docker

build:
	$(CARGO) build --workspace --locked

fmt:
	$(CARGO) fmt --all

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

test:
	$(CARGO) test --workspace --locked

check:
	$(CARGO) check --workspace --all-targets --locked

config-check:
	$(CARGO) run -p elira -- check --config $(CONFIG)

audit:
	$(CARGO) audit

deny:
	$(CARGO) deny check

fuzz:
	@command -v cargo-fuzz >/dev/null 2>&1 || { \
		echo "error: cargo-fuzz is not installed." >&2; \
		echo "       cargo install cargo-fuzz --locked" >&2; \
		exit 1; \
	}
	$(CARGO) fuzz run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_TIME)

load:
	./scripts/load.sh "$(URL)"

bench:
	$(CARGO) bench --workspace

run:
	$(CARGO) run -p elira -- run --config $(CONFIG)

docker:
	docker build -t $(IMAGE) .
