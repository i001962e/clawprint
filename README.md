<p align="center">
  <img src="clawprint.jpg" alt="Clawprint" width="300">
</p>

<h1 align="center">Clawprint</h1>

<p align="center"><b>Every molt leaves a mark. Trace. Verify. Trust.</b></p>

<p align="center">
  <a href="https://github.com/cyntrisec/clawprint/actions/workflows/ci.yml"><img src="https://github.com/cyntrisec/clawprint/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cyntrisec/clawprint/releases/latest"><img src="https://img.shields.io/github/v/release/cyntrisec/clawprint" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

> **Cyntrisec Labs project.** Cyntrisec's main product is [EphemeralML](https://github.com/cyntrisec/EphemeralML) — confidential AI inference with cryptographic receipts ([AIR v1](https://datatracker.ietf.org/doc/draft-tsyrulnikov-rats-attested-inference-receipt/)). Clawprint is a standalone Labs tool for agent audit trails.

Clawprint is a tamper-evident audit trail for OpenClaw agent runs. It silently taps the gateway wire, capturing every trace a molt leaves behind — tool calls, outputs, lifecycle events — and seals them in a SHA-256 hash chain ledger. Replay sessions offline, inspect the evidence through the web dashboard, or query activity from Claude Desktop via MCP.

**Not a proxy or firewall** — Clawprint is a passive observer. It watches the wire, never touches it.

## Features

- **24/7 daemon mode** — Continuous recording to a single ledger, auto-reconnect on disconnect
- **MCP server** — Claude Desktop integration for querying agent activity via natural language
- **Security scanner** — Detect destructive operations, prompt injection, privilege escalation, and anomalies
- **Tamper-evident ledger** — SHA-256 hash chain for every trace with integrity verification
- **Secret redaction** — Automatic redaction of API keys, tokens, JWTs, AWS keys, GitHub PATs, and credentials
- **Offline replay** — Reconstruct agent runs with event breakdowns, agent run sections, and chat reconstruction
- **Web dashboard** — Clean minimal dashboard with filtered/paginated traces, search, and bar charts
- **CLI analytics** — Colored output, event histograms, per-minute timeline, live recording spinner
- **Run diffing** — Compare two runs side-by-side with event kind breakdown
- **Cross-platform** — Prebuilt binaries for Linux, macOS, and Windows
- **CI/CD** — GitHub Actions for testing, linting, and automated release builds

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/cyntrisec/clawprint/master/install.sh | bash

# Or build from source
cargo install --path .

# Run everything in one process (daemon + viewer + MCP)
clawprint serve --daemon --viewer --mcp --out ./clawprints

# Or start individual services
clawprint daemon --gateway ws://127.0.0.1:18789 --out ./clawprints
clawprint record --gateway ws://127.0.0.1:18789 --out ./clawprints

# Open the latest recording in browser
clawprint open --out ./clawprints

# Start MCP server for Claude Desktop
clawprint mcp --out ./clawprints
```

## Commands

| Command | Description |
|---------|-------------|
| `serve` | Run daemon + viewer + MCP in a single process |
| `daemon` | 24/7 continuous recording to a single ledger with auto-reconnect |
| `record` | Record a single session with post-recording summary |
| `mcp` | Start MCP server for Claude Desktop integration |
| `open` | Open the latest (or specific) recording in the web dashboard |
| `list` | List all recorded runs with duration, event count, and storage size |
| `view` | Launch web dashboard for a specific run |
| `replay` | Reconstruct a run offline with agent run sections and chat output |
| `stats` | Show event type histogram, events-per-minute timeline, and agent run count |
| `verify` | Verify SHA-256 hash chain integrity for a recorded run |
| `diff` | Compare two runs with event kind breakdown |

## Serve Mode (All-in-One)

The `serve` command runs any combination of daemon, viewer, and MCP server in a single process. No more juggling multiple terminals.

```bash
# Run everything
clawprint serve --daemon --viewer --mcp --out ./clawprints

# Daemon + viewer only
clawprint serve --daemon --viewer --out ./clawprints

# Daemon + MCP only
clawprint serve --daemon --mcp --out ./clawprints

# Viewer only (browse existing recordings)
clawprint serve --viewer --out ./clawprints
```

Per-service bind addresses can be configured independently:

```bash
clawprint serve --daemon --viewer --mcp \
  --out ./clawprints \
  --viewer-host 10.0.0.1 --viewer-port 8080 \
  --mcp-host 10.0.0.1 --mcp-port 3000 \
  --token mysecret
```

All services share a single Ctrl+C handler for coordinated graceful shutdown.

## Daemon Mode (24/7 Recording)

For always-on agents like OpenClaw, use daemon mode. It records to a single continuous ledger and auto-reconnects on disconnect:

```bash
clawprint daemon --gateway ws://127.0.0.1:18789 --out ./clawprints
```

The daemon:
- Writes to a single `ledger.sqlite` that grows forever
- Automatically groups traces into agent conversation runs
- Reconnects with exponential backoff (1s, 2s, 4s... up to 60s)
- Shuts down gracefully on Ctrl+C / SIGTERM

### As a systemd service

```ini
# /etc/systemd/system/clawprint.service
[Unit]
Description=Clawprint Flight Recorder
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/clawprint serve --daemon --viewer --mcp --out /var/lib/clawprints --token mysecret
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now clawprint
```

## MCP Server (Claude Desktop Integration)

Clawprint includes an MCP (Model Context Protocol) server so you can query agent activity directly from Claude Desktop using natural language.

### Local setup (stdio)

Add to your Claude Desktop config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "clawprint": {
      "command": "clawprint",
      "args": ["mcp", "--out", "/path/to/clawprints"]
    }
  }
}
```

### Remote setup (SSE)

Run the MCP server in SSE mode on the machine with your recordings:

```bash
clawprint mcp --transport sse --host 0.0.0.0 --port 3000 --token mysecret
```

Then on your remote machine, configure Claude Desktop. Since `mcp-remote` enforces HTTPS for non-localhost addresses, use `--allow-http` when connecting over a private network (e.g. WireGuard):

```json
{
  "mcpServers": {
    "clawprint": {
      "command": "npx",
      "args": ["mcp-remote", "http://<host-ip>:3000/mcp", "--allow-http"]
    }
  }
}
```

Requires Node.js >= 20.18.1 on the client machine.

### Available tools

Once connected, Claude can use these tools:

| Tool | What it does |
|------|-------------|
| `clawprint_status` | Recording status, total events, ledger size, integrity |
| `clawprint_list_runs` | List agent conversation runs with duration and tool call count |
| `clawprint_get_run` | Full transcript of an agent run (use `run_id='latest'`) |
| `clawprint_search` | Search event payloads across all history |
| `clawprint_tool_calls` | List tool calls with filtering by run, time, or tool name |
| `clawprint_security_check` | Scan for destructive ops, prompt injection, privilege escalation |
| `clawprint_verify` | Verify hash chain integrity |
| `clawprint_stats` | Event statistics, breakdown by type, timeline |

### Example queries

Ask Claude things like:
- "What did my agent do in the last hour?"
- "Show me all tool calls from today"
- "Run a security check on the latest agent run"
- "Search for any file deletions"
- "Is the recording ledger intact?"

## Security Auditing

The built-in security scanner detects suspicious patterns in recorded traces:

| Category | What it detects |
|----------|----------------|
| Destructive Operations | `rm -rf`, `DROP TABLE`, `DELETE FROM`, `git push --force`, `git reset --hard` |
| Prompt Injection | "ignore previous instructions", role switching, obfuscated base64 payloads |
| Privilege Escalation | `sudo`, `chmod 777`, writes to `/etc/`, `/root/` |
| External Access | `curl`/`wget` in tool calls, HTTP URLs in tool arguments |
| Cost Anomaly | >50 tool calls per agent run, >100 traces per minute |

Use via MCP: ask Claude "run a security check on today's activity"

Or programmatically via the `clawprint::security::scan_events()` API.

## Web Dashboard

The `view` command launches a minimal web dashboard at `http://127.0.0.1:8080`:

- **Dashboard page** — Summary stats (impressions, traces, evidence), clickable run list with status badges and integrity indicators
- **Run detail page** — Evidence breakdown bar chart, filter buttons per trace kind, text search with debounce, paginated trace log (50/page), collapsible JSON payloads, color-coded trace cards

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/runs` | List all runs with metadata and size |
| `GET /api/runs/:id` | Run metadata (event count, root hash, chain validity) |
| `GET /api/runs/:id/events` | Paginated events with `?kind=X&search=Y&page=N&per_page=50` |
| `GET /api/runs/:id/stats` | Event breakdown, timeline, agent run count |

## Storage Format

Each run is a self-contained "case file":

```
clawprints/
  runs/
    <run_id>/
      ledger.sqlite      # Events with SHA-256 hash chain (WAL mode, synchronous=FULL)
      artifacts/          # Compressed blobs (zstd)
        <hash_prefix>/<hash>.zst
      meta.json           # Run metadata + root hash
  ledger.sqlite           # Continuous ledger (daemon mode)
```

### SQLite Schema

Events are stored with sequential IDs, timestamps, event kind, JSON payload, span/parent IDs, and hash chain fields (`hash_prev`, `hash_self`). Artifacts are deduplicated by content hash and compressed with Zstandard.

## Event Types

| Kind | Description |
|------|-------------|
| `RUN_START` / `RUN_END` | Session boundaries |
| `AGENT_EVENT` | Raw gateway stream events (tool calls, results, agent lifecycle) |
| `TOOL_CALL` / `TOOL_RESULT` | Direct tool invocations and results |
| `OUTPUT_CHUNK` | Streamed assistant output (chat messages) |
| `PRESENCE` / `TICK` | Gateway heartbeat and event loop ticks |
| `SHUTDOWN` | Gateway shutdown signal |
| `CUSTOM` | Unknown/custom event types |

## Architecture

```
                                                        Storage
 OpenClaw       WebSocket        Clawprint             (SQLite + zstd)
 Gateway  <------------------>  Daemon/Recorder  --->  ledger.sqlite
           (observer role)         |
                                   |--- MCP Server ---> Claude Desktop
                                   |
                                   v
                              Web Viewer  <---  Browser
                              (Axum HTTP)       (Dashboard UI)
```

### Modules

| Module | Role |
|--------|------|
| `gateway` | WebSocket client for OpenClaw Gateway protocol v3 (req/res/event frames) |
| `record` | Recording session coordinator with live progress spinner |
| `daemon` | 24/7 continuous recording with auto-reconnect |
| `ledger` | Single continuous SQLite ledger with agent run grouping |
| `mcp` | MCP server for Claude Desktop integration (8 tools) |
| `security` | Security scanner for detecting suspicious patterns |
| `storage` | Per-session SQLite ledger with hash chain, artifact store, filtered queries |
| `replay` | Offline replay with agent run grouping and chat reconstruction |
| `viewer` | Axum web server with dashboard UI and REST API |
| `redact` | Secret detection and redaction (regex-based, supports JWT/AWS/GitHub patterns) |

## Authentication

Clawprint auto-discovers the gateway auth token from `~/.openclaw/openclaw.json`:

```json
{
  "gateway": {
    "auth": {
      "token": "your-token-here"
    }
  }
}
```

Or pass it directly: `clawprint record --token <token>`

## Remote Access with WireGuard

If Clawprint runs on a remote machine (AWS, Mac Mini, etc.) and you want to access the dashboard or MCP server from other devices, use WireGuard to create an encrypted private network. No ports are exposed to the public internet — only the WireGuard UDP port.

### Install WireGuard

```bash
# Ubuntu/Debian
sudo apt install wireguard

# macOS
brew install wireguard-tools

# Windows — download from https://www.wireguard.com/install/
```

### Generate keys (on each machine)

```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

On Windows, the WireGuard GUI generates keys automatically when you add a new tunnel.

### Server config (Clawprint host)

```ini
# /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

# macOS client
[Peer]
PublicKey = <client1-public-key>
AllowedIPs = 10.0.0.2/32

# Linux client
[Peer]
PublicKey = <client2-public-key>
AllowedIPs = 10.0.0.3/32

# Windows client
[Peer]
PublicKey = <client3-public-key>
AllowedIPs = 10.0.0.4/32
```

### Client config (macOS / Linux)

```ini
# /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.2/24
PrivateKey = <client-private-key>

[Peer]
PublicKey = <server-public-key>
Endpoint = <server-public-ip>:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

### Client config (Windows)

Open the WireGuard app, click **Add Tunnel > Add empty tunnel**, and paste:

```ini
[Interface]
Address = 10.0.0.4/24
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
Endpoint = <server-public-ip>:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

### Start the tunnel

```bash
# Linux / macOS
sudo wg-quick up wg0

# Enable on boot
sudo systemctl enable wg-quick@wg0   # Linux
sudo brew services start wireguard    # macOS
```

On Windows, click **Activate** in the WireGuard GUI.

### Firewall

Only UDP port 51820 needs to be open on the server:

- **AWS**: Add an inbound security group rule for UDP 51820
- **Mac Mini behind a router**: Forward UDP 51820 to the Mac Mini's local IP

### Run Clawprint over WireGuard

Bind to the WireGuard IP so Clawprint is only reachable through the tunnel:

```bash
# All-in-one: daemon + viewer + MCP bound to WireGuard interface
clawprint serve --daemon --viewer --mcp \
  --out ./clawprints \
  --viewer-host 10.0.0.1 --mcp-host 10.0.0.1 \
  --token mysecret

# Or run services individually
clawprint open --out ./clawprints --host 10.0.0.1 --token mysecret
clawprint mcp --transport sse --host 10.0.0.1 --port 3000 --token mysecret --out ./clawprints
```

From any client on the WireGuard network, access `http://10.0.0.1:8080` in a browser or configure Claude Desktop:

```json
{
  "mcpServers": {
    "clawprint": {
      "command": "npx",
      "args": ["mcp-remote", "http://10.0.0.1:3000/mcp", "--allow-http"]
    }
  }
}
```

Requires Node.js >= 20.18.1 on the client machine. The `--allow-http` flag is safe here since `10.0.0.1` is the private WireGuard interface (encrypted at the tunnel level).

### Verify the tunnel

```bash
sudo wg show    # Check handshake and transfer stats
ping 10.0.0.1   # Test connectivity
```

### Claude Desktop MCP config over WireGuard

Claude Desktop requires `npx mcp-remote` as a stdio-to-SSE bridge. Since `mcp-remote` enforces HTTPS for non-localhost addresses, use `--allow-http` for private WireGuard IPs:

```json
{
  "mcpServers": {
    "clawprint": {
      "command": "npx",
      "args": ["mcp-remote", "http://10.0.0.1:3000/mcp", "--allow-http"]
    }
  }
}
```

Requires Node.js >= 20.18.1 on the client machine. The `--allow-http` flag is safe here since traffic is encrypted at the WireGuard tunnel level.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--gateway` | `ws://127.0.0.1:18789` | Gateway WebSocket URL |
| `--out` | `./clawprints` | Output directory for recordings |
| `--token` | auto-discovered | Gateway auth token (record/daemon) or HTTP bearer token (view/open/mcp) |
| `--no-redact` | `false` | Disable secret redaction |
| `--batch-size` | `100` | SQLite batch commit size |
| `--host` | `127.0.0.1` (viewer/open), `0.0.0.0` (MCP SSE) | Bind address for viewer/MCP |
| `--port` | `8080` / `3000` | Web viewer / MCP SSE server port |
| `--viewer-host` | `127.0.0.1` | Viewer bind address (`serve` only) |
| `--viewer-port` | `8080` | Viewer port (`serve` only) |
| `--mcp-host` | `0.0.0.0` | MCP SSE bind address (`serve` only) |
| `--mcp-port` | `3000` | MCP SSE port (`serve` only) |
| `--transport` | `stdio` | MCP transport: `stdio` (local) or `sse` (network) |
| `RUST_LOG` | `clawprint=info` | Log level (set to `clawprint=debug` for verbose output) |

## Integrity Verification

Every trace includes a SHA-256 hash computed from its canonical form. Each trace's `hash_prev` points to the previous trace's `hash_self`, forming a tamper-evident chain. The `verify` command inspects the entire chain of evidence and reports `INTACT` or `COMPROMISED`.

```bash
$ clawprint verify --run <run_id> --out ./clawprints
  Inspecting chain of evidence for a1b2c3d4... INTACT
  Traces:    1234
  Root hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

## Installation

### Prebuilt binaries

```bash
curl -fsSL https://raw.githubusercontent.com/cyntrisec/clawprint/master/install.sh | bash
```

Downloads the latest release binary for your platform (Linux x86_64/aarch64, macOS Intel/Apple Silicon). Falls back to building from source if no binary is available.

### Windows

Download `clawprint-windows-x86_64.exe` from the [latest release](https://github.com/cyntrisec/clawprint/releases/latest) and add it to your PATH.

### From source

```bash
cargo install --path .
```

Or manually:

```bash
cargo build --release
cp target/release/clawprint ~/.local/bin/
```

## Building

```bash
# Development
cargo build

# Release (optimized, LTO, stripped)
cargo build --release

# Run tests
cargo test

# Without web viewer or MCP features
cargo build --no-default-features
```

## Releasing

Releases are automated via GitHub Actions. To publish a new version:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This builds binaries for all 5 platforms (Linux x86_64/aarch64, macOS Intel/Apple Silicon, Windows x86_64) and creates a GitHub Release with the assets attached.

## License

MIT
