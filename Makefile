.PHONY: all check clean

all: build

check: fmt test clippy

test:
	cargo test --all-features

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --tests -- -D warnings

clean:
	cargo clean

build:
	cargo build --release