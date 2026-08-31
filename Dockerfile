FROM rust:1-bookworm AS build

ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools clang \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY bpf ./bpf
RUN mkdir src \
    && printf 'fn main() {}\n' > src/main.rs \
    && printf '\n' > src/lib.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl \
    && rm -rf src
COPY src ./src
RUN find src -type f -exec touch {} + \
    && cargo build --release --locked --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian12
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/egresso /egresso
ENTRYPOINT ["/egresso"]
