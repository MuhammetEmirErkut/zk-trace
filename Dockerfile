# syntax=docker/dockerfile:1
# ------------------------------------------------------------------------------
# Build Stage: Compile ZKTrace statically with Rust Stable
# ------------------------------------------------------------------------------
FROM rust:latest AS builder

WORKDIR /build

# Copy dependency manifests for layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/zktrace-core/Cargo.toml crates/zktrace-core/
COPY crates/zktrace-circuits/Cargo.toml crates/zktrace-circuits/
COPY crates/zktrace-prover/Cargo.toml crates/zktrace-prover/
COPY crates/zktrace-verifier/Cargo.toml crates/zktrace-verifier/
COPY crates/zktrace-ledger/Cargo.toml crates/zktrace-ledger/
COPY crates/zktrace-mcp/Cargo.toml crates/zktrace-mcp/
COPY crates/zktrace-cli/Cargo.toml crates/zktrace-cli/

# Copy all source files
COPY crates crates/

# Build optimized release binary with cargo layer caching
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --bin zktrace && \
    strip target/release/zktrace

# ------------------------------------------------------------------------------
# Runtime Stage: Minimal Distroless / Scratch Base with Non-Root User
# ------------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

# Copy stripped binary from builder
COPY --from=builder --chown=nonroot:nonroot /build/target/release/zktrace /usr/local/bin/zktrace

# Expose default REST Verifier port
EXPOSE 8080

# Run as unprivileged user
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/zktrace"]
CMD ["serve", "--port", "8080"]
