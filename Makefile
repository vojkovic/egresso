.PHONY: build test fmt lint clean

build:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt --all

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
