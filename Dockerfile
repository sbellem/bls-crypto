FROM rust:1.77.2-bookworm

RUN apt-get update && apt-get install --yes --no-install-recommends \
        gdb \
        vim \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy
RUN cargo install cargo-upgrades cargo-edit

WORKDIR /usr/src/bls-crypto

COPY Cargo.lock Cargo.toml .
COPY benches benches
COPY examples examples
COPY src src

RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --examples --tests
