#!/bin/bash
set -e

# Blocknet Node Entrypoint Script
# Handles wallet initialization and auto-mining

echo "=========================================="
echo "  Blocknet Node Starting"
echo "=========================================="

# Build command arguments
ARGS="--daemon"
ARGS="$ARGS --data ${BLOCKNET_DATA_DIR}"
ARGS="$ARGS --wallet ${BLOCKNET_WALLET_FILE}"
ARGS="$ARGS --listen ${BLOCKNET_LISTEN}"

# Add API if configured
if [ -n "$BLOCKNET_API_ADDR" ]; then
    ARGS="$ARGS --api ${BLOCKNET_API_ADDR}"
    echo "API server: ${BLOCKNET_API_ADDR}"
fi

# Add explorer if configured
if [ -n "$BLOCKNET_EXPLORER_ADDR" ]; then
    ARGS="$ARGS --explorer ${BLOCKNET_EXPLORER_ADDR}"
    echo "Block explorer: ${BLOCKNET_EXPLORER_ADDR}"
fi

# Seed mode for bootstrap nodes
if [ "$BLOCKNET_SEED_MODE" = "true" ]; then
    ARGS="$ARGS --seed"
    echo "Running as seed node (persistent identity)"
fi

echo "Data directory: ${BLOCKNET_DATA_DIR}"
echo "Wallet file: ${BLOCKNET_WALLET_FILE}"
echo "P2P listen: ${BLOCKNET_LISTEN}"
echo "=========================================="

# Function to start mining via API after daemon is ready
start_mining() {
    if [ "$BLOCKNET_AUTO_MINE" != "true" ]; then
        return
    fi
    
    echo "Waiting for API to be ready..."

    # Wait for cookie file to appear (means API is up)
    COOKIE_FILE="${BLOCKNET_DATA_DIR}/api.cookie"
    for i in {1..120}; do
        if [ -f "$COOKIE_FILE" ]; then
            TOKEN=$(cat "$COOKIE_FILE")
            # Verify API responds with auth
            if curl -sf -H "Authorization: Bearer ${TOKEN}" \
                "http://localhost:${BLOCKNET_API_ADDR##*:}/api/status" > /dev/null 2>&1; then
                echo "API is ready!"
                break
            fi
        fi
        sleep 1
    done

    if [ -z "$TOKEN" ]; then
        echo "Warning: Could not authenticate to API after 120s"
        return
    fi
    
    # Set mining threads
    if [ -n "$BLOCKNET_MINE_THREADS" ] && [ "$BLOCKNET_MINE_THREADS" != "1" ]; then
        echo "Setting mining threads to ${BLOCKNET_MINE_THREADS}..."
        curl -sf -X POST "http://localhost:${BLOCKNET_API_ADDR##*:}/api/mining/threads" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"threads\": ${BLOCKNET_MINE_THREADS}}" || true
    fi
    
    # Start mining
    echo "Starting miner..."
    RESULT=$(curl -sf -X POST "http://localhost:${BLOCKNET_API_ADDR##*:}/api/mining/start" \
        -H "Authorization: Bearer ${TOKEN}" 2>&1) || true
    
    if echo "$RESULT" | grep -q '"running":true'; then
        echo "Mining started successfully!"
        echo "  Threads: ${BLOCKNET_MINE_THREADS:-1}"
        echo "  RAM usage: ~$((${BLOCKNET_MINE_THREADS:-1} * 2))GB"
    else
        echo "Mining start response: $RESULT"
    fi
}

# Function to handle wallet password
# The daemon prompts for password on stdin
# For new wallets: needs password twice (enter + confirm)
# For existing wallets: needs password once
run_daemon() {
    if [ -z "$BLOCKNET_WALLET_PASSWORD" ]; then
        echo "Error: BLOCKNET_WALLET_PASSWORD not set"
        echo "This is required for wallet encryption"
        exit 1
    fi
    
    if [ -f "$BLOCKNET_WALLET_FILE" ]; then
        # Existing wallet - send password once
        echo "Opening existing wallet..."
        echo "$BLOCKNET_WALLET_PASSWORD" | /app/blocknet $ARGS
    else
        # New wallet - send password twice (enter + confirm)
        echo "Creating new wallet..."
        printf '%s\n%s\n' "$BLOCKNET_WALLET_PASSWORD" "$BLOCKNET_WALLET_PASSWORD" | /app/blocknet $ARGS
    fi
}

# Start mining in background after daemon is up
start_mining &

# Run the daemon (this blocks)
run_daemon
