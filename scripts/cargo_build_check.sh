#!/usr/bin/env bash

# check fmt, clippy, testcase

set -e
cd ..

cargo fmt -- --check
#cargo clippy --all-features -- -D warnings
cargo test --all-features

exit 0
