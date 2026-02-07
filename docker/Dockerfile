# Blocknet Node Dockerfile
# Multi-stage build: Build environment -> Runtime environment

# =============================================================================
# Stage 1: Build environment with Go and Rust
# =============================================================================
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ARG GO_VERSION=1.22.5
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build Rust crypto library
RUN cd crypto-rs && cargo build --release

# Build Go binary with static linking
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o blocknet .

# =============================================================================
# Stage 2: Runtime environment (minimal)
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash blocknet

# Create directories
RUN mkdir -p /app /data /wallet && chown -R blocknet:blocknet /app /data /wallet

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/blocknet /app/blocknet
RUN chmod +x /app/blocknet

# Copy entrypoint script
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER blocknet

# Environment variables
ENV BLOCKNET_DATA_DIR="/data"
ENV BLOCKNET_WALLET_FILE="/wallet/wallet.dat"
ENV BLOCKNET_LISTEN="/ip4/0.0.0.0/tcp/28080"
ENV BLOCKNET_API_ADDR="0.0.0.0:8332"
ENV BLOCKNET_EXPLORER_ADDR=":8080"
ENV BLOCKNET_WALLET_PASSWORD=""
ENV BLOCKNET_AUTO_MINE="false"
ENV BLOCKNET_MINE_THREADS="1"
ENV BLOCKNET_SEED_MODE="false"

# Expose ports
EXPOSE 28080 8332 8080

# Volumes for persistence
VOLUME ["/data", "/wallet"]

# Health check via API
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -sf -H "Authorization: Bearer $(cat /data/api.cookie 2>/dev/null)" http://localhost:8332/api/status || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
