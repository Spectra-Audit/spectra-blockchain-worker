# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

The Spectra Blockchain Worker is a Python service that monitors blockchain events from smart contracts and synchronizes them with the Spectra backend API. It consists of two main scouts: FeaturedScout for payment/featured project events and ProScout for staking/subscription events.

## Commands

### Development
```bash
# Setup virtual environment
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install web3 requests pytest

# Configure environment
cp .env.example .env  # Edit with your settings
```

### Running the Worker
```bash
# Run both scout services together
python -m scout run

# Check current status and last processed blocks
python -m scout status

# Run individual scouts
python -m scout.featured_scout --log-level DEBUG
python -m scout.pro_scout

# Process a single window then exit (useful for testing)
python -m scout.featured_scout --once
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_featured_scout.py

# Run with verbose output
pytest -v
```

## Architecture

### Core Components

**ScoutApp** (`scout/main.py`) - Main orchestrator that coordinates all services:
- Manages application lifecycle (start/stop/shutdown)
- Provides shared resources (database, backend client, WebSocket pool)
- Handles signal-based shutdown for clean termination

**FeaturedScout** (`scout/featured_scout.py`) - Monitors `VeritasPaymentsAndBids` contract:
- Processes `RoundFinalized` events → updates project featured status
- Processes `Paid` events → marks projects as paid
- Uses both HTTP polling and WebSocket subscriptions
- Maintains last processed block in database

**ProScout** (`scout/pro_scout.py`) - Monitors `VeritaStaking` contract:
- Processes `StakeStarted` events → schedules tier activation (7-day delay)
- Processes `TierUpgraded` events → updates user subscription
- Processes `UnstakeRequested` events → immediately revokes pro benefits
- Uses priority queue for efficient activation scheduling

**DatabaseManager** (`scout/database_manager.py`) - Shared SQLite persistence:
- Thread-safe connections with WAL mode
- Stores processed log tracking, pending activations, metadata
- Prevents duplicate event processing
- Schema: `processed_logs`, `pending_activations`, `featured_projects`, `meta`

**BackendClient** (`scout/backend_client.py`) - HTTP client for Spectra API:
- JWT token management with automatic refresh
- Retry logic with exponential backoff
- Thread-safe session management
- Integrates with SIWE authenticator

### Event Processing Flow

```
Blockchain Event → RPC/WS → Event Decoding → Deduplication → Backend API Update
```

1. **Event Discovery**: HTTP polling + WebSocket subscriptions
2. **Event Decoding**: Uses contract ABIs to decode log data
3. **Deduplication**: Checks `processed_logs` table to prevent reprocessing
4. **State Update**: PATCH requests to backend API
5. **Progress Tracking**: Stores last processed block number

### Configuration

The worker is configured via environment variables in `.env`:

**Required:**
- `RPC_HTTP_URL` or `RPC_HTTP_URLS`: Ethereum RPC endpoints
- `ADMIN_ACCESS_TOKEN` / `ADMIN_REFRESH_TOKEN`: Backend authentication

**Common Settings:**
- `CONTRACT_ADDRESS`: Smart contract address
- `API_BASE_URL`: Backend API endpoint (default: http://localhost:8000/v1)
- `POLL_INTERVAL_SEC`: 8 seconds default
- `REORG_CONF`: 5 confirmations default
- `DB_PATH`: SQLite database file path

### Authentication

Uses SIWE (Sign-In with Ethereum) authentication:
1. Admin wallet loaded/stored in database
2. Tokens generated for backend API access
3. Automatic token refresh handled by BackendClient

### State Management

**FeaturedScout State:**
- `featured_last_block`: Last processed block number
- `featured_active_rpc_index`: Active RPC provider index
- Project ID mappings for hex ↔ UUID conversion

**ProScout State:**
- `pro_last_block`: Last processed block number
- `pending_activations`: Queue of scheduled tier activations
- `pro_active_rpc_index`: Active RPC provider index

### Error Handling & Resilience

- **RPC Failover**: Multiple RPC providers with automatic failover
- **WebSocket Recovery**: Falls back to HTTP polling on WebSocket failures
- **Retry Logic**: Exponential backoff for API calls
- **State Recovery**: Database persistence enables clean restarts
- **Circuit Breakers**: Configurable retry limits and delays

## Smart Contract Events

### FeaturedScout Events
```solidity
event RoundFinalized(uint64 indexed roundId, LeaderEntry[10] winners, uint8 count, uint256 totalToAdmin);
event Paid(address indexed payer, address indexed creator, bytes32 indexed projectId,
          uint256 amountPaidFees, uint8 numberOfContracts, uint256 featuredBid, uint64 roundId);
```

### ProScout Events
```solidity
event StakeStarted(address indexed account, uint8 indexed tier, uint256 amount,
                  uint256 stakedAt, uint256 activatesAt, uint256 earliestUnstakeAt);
event TierUpgraded(address indexed account, uint8 indexed oldTier, uint8 indexed newTier,
                   uint256 newAmount, uint256 stakedAt, uint256 activatesAt, uint256 earliestUnstakeAt);
event UnstakeRequested(address indexed account, uint8 indexed tier, uint256 amount,
                       uint256 unstakeRequestedAt, uint256 withdrawAvailableAt,
                       uint16 feeBps, uint256 feeAmount, uint256 netAmount);
```

## Development Notes

- **No Blockchain Required for Tests**: Uses comprehensive mocking in `tests/conftest.py`
- **Threading**: All components are thread-safe with proper locking
- **Logging**: Structured logging with configurable levels
- **Hot Reload**: Configuration changes require restart
- **Database**: SQLite with WAL mode for concurrent access