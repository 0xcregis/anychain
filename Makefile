.PHONY: all check clean

all: build

check: fmt test clippy

test:
	(command -v cargo-nextest && cargo nextest run --all-features --workspace) || cargo test --all-features --workspace

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --tests -- -D warnings

clean:
	cargo clean

build:
	cargo build --release

build-linux-server:
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl	
	rustup target add aarch64-unknown-linux-musl
	cargo build --release --target aarch64-unknown-linux-musl

build-ios:
	rustup target add aarch64-apple-ios
	cargo build --release --target aarch64-apple-ios