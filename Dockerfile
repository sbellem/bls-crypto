FROM rust:1.77.2-bookworm

RUN cargo install cargo-upgrades cargo-edit

WORKDIR /usr/src/bls-crypto

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build
