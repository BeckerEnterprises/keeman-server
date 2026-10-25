.PHONY: check fmt build sqlx-check sqlx-prepare

# Scratch database for compile-time checked queries (never real data).
SQLX_DB := $(CURDIR)/target/sqlx-dev.db
SQLX_URL := sqlite://$(SQLX_DB)

# Everything that must pass before a change is merged.
check: sqlx-check
	cargo fmt --all --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --locked
	cargo audit
	cargo deny check

fmt:
	cargo fmt --all

build:
	cargo build --locked

# .sqlx/ must match the queries and migrations.
sqlx-check:
	mkdir -p $(dir $(SQLX_DB))
	rm -f $(SQLX_DB)*
	DATABASE_URL=$(SQLX_URL) cargo sqlx database setup
	DATABASE_URL=$(SQLX_URL) cargo sqlx prepare --check -- --all-targets

sqlx-prepare:
	mkdir -p $(dir $(SQLX_DB))
	rm -f $(SQLX_DB)*
	DATABASE_URL=$(SQLX_URL) cargo sqlx database setup
	DATABASE_URL=$(SQLX_URL) cargo sqlx prepare -- --all-targets
