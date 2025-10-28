# Spectra Blockchain Worker

Spectra's blockchain worker is a standalone Python service that monitors on-chain
activity and mirrors the results into the Spectra backend. Offloading this work
from the main API keeps user-facing requests fast while still allowing the
platform to react quickly to smart contract events.

## Features

- **Featured contract watcher** – consumes `RoundFinalized` and `Paid` events and
  forwards the results to the backend API.
- **Pro scout** – keeps user subscription state in sync by reconciling payments
  against blockchain activity.
- **Shared persistent state** – maintains an SQLite database that allows the
  different scouts to coordinate their progress and resume cleanly after restarts.
- **CLI tooling** – run the worker, inspect its status, or seed metadata directly
  from the command line.

## Repository structure

```
├── scout/                 # Worker source code
│   ├── main.py            # CLI entry point and application wiring
│   ├── featured_scout.py  # Featured contract watcher
│   ├── pro_scout.py       # Subscription reconciliation logic
│   ├── backend_client.py  # Lightweight REST client for the Spectra API
│   └── database_manager.py# SQLite schema management and helpers
└── tests/                 # Unit tests (pytest)
```

## Prerequisites

- Python 3.10 or newer (3.11+ recommended)
- Access to an Ethereum-compatible RPC endpoint
- Admin credentials for the Spectra backend API

Install the Python dependencies into a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install web3 requests pytest
```

## Configuration

The worker is configured entirely through environment variables. Start by
copying `.env.example` to `.env` and updating the values for your deployment;
every variable mentioned below is documented there with inline guidance. The
most important settings are listed below.

| Variable | Description |
| --- | --- |
| `RPC_HTTP_URL` | **Required.** HTTPS URL for the Ethereum JSON-RPC endpoint used to pull logs. |
| `RPC_WS_URLS` | Optional comma-separated list of WebSocket RPC endpoints used for live `eth_subscribe` streams. |
| `ADMIN_ACCESS_TOKEN` | **Required.** Admin token used to authenticate with the Spectra backend. |
| `API_BASE_URL` | Base URL for the Spectra backend API. Defaults to `http://localhost:8000/v1`. |
| `CONTRACT_ADDRESS` | Address of the Featured contract that emits the events being tracked. |
| `CHAIN_ID` | Optional chain ID override for signing requests. |
| `PROJECT_ID_RESOLVER_URL` | Optional HTTP endpoint that maps contract project IDs to backend UUIDs. |
| `DB_PATH` | Path to the SQLite database file shared by the scouts. Defaults to `featured_scout.db`. |
| `SCOUT_DB_PATH` | Overrides `DB_PATH` for the combined `scout` application. |
| `POLL_INTERVAL_SEC` | Seconds to wait between blockchain polling iterations. Default: `8`. |
| `REORG_CONF` | Number of confirmations required before a block is considered final. Default: `5`. |
| `START_BLOCK` | Block height to begin indexing from. Use `latest` (default) to start from the current safe block. |
| `DEFAULT_USER_TIER` | Default tier assigned to new users by the pro scout. |
| `PRO_TIER_SET` | Comma-separated list of tiers that unlock pro features. |
| `LOG_LEVEL` | Logging verbosity (e.g., `INFO`, `DEBUG`). |

## Usage

### Running the combined worker

The recommended way to operate the worker is through the consolidated CLI:

```bash
python -m scout run
```

This starts both the Featured and Pro scouts, waits for blockchain events, and
publishes updates to the Spectra backend. When `RPC_WS_URLS` is provided the
worker maintains live WebSocket subscriptions in addition to the historical HTTP
pollers, automatically falling back to HTTP-only mode if the socket connection
drops. The process listens for `SIGINT` and `SIGTERM` to perform a clean
shutdown. To inspect the last processed blocks without running the worker,
execute:

```bash
python -m scout status
```

### Running the Featured scout directly

When you only need the Featured contract watcher (for example during
troubleshooting), invoke its dedicated CLI:

```bash
python -m scout.featured_scout --log-level DEBUG
```

Useful options include:

- `--once` – Process a single polling window and exit.
- `--seed-mapping PROJECT_HEX=UUID` – Seed project ID to backend UUID mappings.

### Running the Pro scout directly

The Pro scout can likewise be started in isolation:

```bash
python -m scout.pro_scout
```

Refer to `scout/pro_scout.py` for additional CLI options relating to tier
configuration and dry-run modes.

## Development

Run the unit test suite with pytest:

```bash
pytest
```

The tests exercise the shared database layer and backend client utilities. They
expect the optional dependencies listed earlier to be installed and will run
entirely against the local codebase—no blockchain access is required.

## Troubleshooting

- **Missing dependencies:** Ensure the virtual environment is active and that
  `web3` and `requests` are installed. The CLI imports them eagerly.
- **Failed RPC requests:** Check that `RPC_HTTP_URL` points to a healthy JSON-RPC
  endpoint and that your account has sufficient access.
- **Authentication errors:** Verify the `ADMIN_ACCESS_TOKEN` value and, if you
  are running against a remote backend, confirm that `API_BASE_URL` is correct.

For more implementation details, dive into the modules within the `scout/`
package. Each file contains extensive inline documentation describing the data
flow and error-handling strategy.
