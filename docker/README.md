# Blocknet Docker Deployment

Run a full Blocknet node with wallet, API, block explorer, and optional mining.

## Quick Start

```bash
cd docker

# Create environment file
cp .env.example .env
# Edit .env and set BLOCKNET_WALLET_PASSWORD

# Build and start
docker-compose up -d

# View logs
docker-compose logs -f blocknet-node

# Check status
curl http://localhost:8332/api/status
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| P2P Network | 28080 | Blockchain peer-to-peer network |
| API Server | 8332 | JSON API for wallet/node control |
| Block Explorer | 8080 | Web-based block explorer |

## Configuration

Environment variables in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCKNET_WALLET_PASSWORD` | (required) | Wallet encryption password |
| `BLOCKNET_AUTO_MINE` | `false` | Start mining automatically |
| `BLOCKNET_MINE_THREADS` | `1` | Mining threads (~2GB RAM each) |

## Mining

### Start mining manually via API:

```bash
# Get auth token
TOKEN=$(docker exec blocknet-node cat /data/api.cookie)

# Start mining
curl -X POST http://localhost:8332/api/mining/start \
  -H "Authorization: Bearer $TOKEN"

# Check status
curl http://localhost:8332/api/mining \
  -H "Authorization: Bearer $TOKEN"

# Set threads (each needs 2GB RAM)
curl -X POST http://localhost:8332/api/mining/threads \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"threads": 2}'
```

### Auto-mine on startup:

```bash
# In .env:
BLOCKNET_AUTO_MINE=true
BLOCKNET_MINE_THREADS=1
```

## Auto-Updates

Enable the updater service to automatically rebuild when GitHub updates:

```bash
# Start with updater
docker-compose --profile updater up -d

# Check updater logs
docker-compose logs -f blocknet-updater
```

The updater checks GitHub every 5 minutes and rebuilds the node on new commits.

## Wallet Management

### View wallet address:

```bash
TOKEN=$(docker exec blocknet-node cat /data/api.cookie)
curl http://localhost:8332/api/wallet \
  -H "Authorization: Bearer $TOKEN"
```

### Check balance:

```bash
curl http://localhost:8332/api/wallet/balance \
  -H "Authorization: Bearer $TOKEN"
```

### Backup wallet:

```bash
# Copy wallet file from volume
docker cp blocknet-node:/wallet/wallet.dat ./wallet-backup.dat
```

## Data Persistence

Data is stored in Docker volumes:
- `blocknet-data` - Blockchain data
- `blocknet-wallet` - Encrypted wallet

To backup:
```bash
docker run --rm -v blocknet-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/blocknet-data.tar.gz /data

docker run --rm -v blocknet-wallet:/wallet -v $(pwd):/backup alpine \
  tar czf /backup/blocknet-wallet.tar.gz /wallet
```

## Resource Requirements

| Component | RAM | CPU | Disk |
|-----------|-----|-----|------|
| Node only | 512MB | 1 core | 10GB+ |
| + 1 miner thread | 2.5GB | 1 core | - |
| + 2 miner threads | 4.5GB | 2 cores | - |

Mining uses Argon2id with 2GB memory per thread for ASIC resistance.

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs blocknet-node

# Common issue: wallet password not set
# Solution: Set BLOCKNET_WALLET_PASSWORD in .env
```

### Can't connect to API
```bash
# Check if container is running
docker-compose ps

# Check if API is listening
docker exec blocknet-node curl -s localhost:8332/api/status
```

### Mining not starting
```bash
# Check if synced first (mining requires synced chain)
curl http://localhost:8332/api/status

# Check miner status
TOKEN=$(docker exec blocknet-node cat /data/api.cookie)
curl http://localhost:8332/api/mining -H "Authorization: Bearer $TOKEN"
```
