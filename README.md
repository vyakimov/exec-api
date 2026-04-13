# exec-api

**Run allowlisted shell commands on a remote host, over HTTP, with JSON in and JSON out.**

Built for LLM harnesses. Your agent runs on one machine; the tools it needs (compilers, CLIs, scripts, build systems) live on another. exec-api lets the harness reach across that gap safely: every invocation is a single JSON request, every result is a structured JSON envelope — easy to parse, easy to log, impossible to confuse with normal shell output.

## Why use this

- **Remote execution for agents.** Run an LLM loop in one environment and execute its commands in another (different OS, different network, dedicated sandbox VM) without giving it shell access.
- **JSON in, JSON out.** Commands are wrapped in JSON so a model can construct them reliably and a harness can parse the result without regex-scraping stdout/stderr.
- **Safe by default.** Frozen allowlist, no shell interpolation, bearer-token auth, timeouts, file-size caps. The agent can only do what you've explicitly permitted.
- **Tiny.** A single FastAPI server and a stdlib-only Python client. No queue, no database, no plugin system.

## Security Model

- **Frozen allowlist** — only commands in `allowlist.txt` can run. Loaded once at startup.
- **No shell execution** — `subprocess.exec` with an argv list. No `sh -c`, no interpolation, no injection surface.
- **Bearer-token auth** — every request requires a token (constant-time comparison).
- **Timeouts** — 30 seconds per command.
- **File uploads** — basename-only validation, 5 MiB per file, 10 MiB total, per-request temp dir with guaranteed cleanup.
- **Stdin limits** — optional UTF-8 stdin forwarding, capped at 256 KiB.

## Quick Start

```bash
pip install -r requirements.txt

# Define what the agent is allowed to run
cp allowlist.txt.example allowlist.txt
# Edit allowlist.txt

# Optional: pin commands to absolute paths instead of $PATH lookup
cp command-paths.json.example command-paths.json

# Start the server
EXEC_API_TOKEN=your-secret-token uvicorn server:app --host 127.0.0.1 --port 8019
```

Then from your harness host:

```bash
EXEC_API_HOST=remote-box:8019 EXEC_API_TOKEN=your-secret-token \
  client/exec-api --json echo hello
```

### macOS launchd service

To install as a persistent launchd service:

```bash
cp .env.example .env
# Edit .env — set EXEC_API_TOKEN and any extra env vars your commands need

./install-launchd.sh --host 127.0.0.1 --port 8019
```

The script reads all `KEY=VALUE` pairs from `.env` and injects them into the launchd plist. Options:

| Flag | Default | Purpose |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8019` | Bind port |
| `--label` | `exec-api` | launchd service label |
| `--env-file` | `.env` (in repo dir) | Path to env file |

To update after editing `.env`:

```bash
launchctl kickstart -k gui/$(id -u)/exec-api
```

## Configuration

| File / Env Var | Purpose |
|---|---|
| `allowlist.txt` | One command name per line. `#` comments and blank lines ignored. Gitignored — copy from `allowlist.txt.example`. |
| `command-paths.json` | Optional `{"command": "/path"}` map for commands that should not be resolved from `$PATH`. Gitignored — copy from `command-paths.json.example`. |
| `.env` | `KEY=VALUE` pairs passed to the service via `install-launchd.sh`. Must contain `EXEC_API_TOKEN`. Gitignored — copy from `.env.example`. |

## Client

The `client/` directory contains a stdlib-only Python client (Python 3, no dependencies). Drop it onto the harness host and call it directly.

### Environment Variables

| Env Var | Default | Purpose |
|---|---|---|
| `EXEC_API_HOST` | `127.0.0.1:8019` | Server host:port |
| `EXEC_API_TOKEN` | (required) | Bearer token |

### Usage

```bash
# Basic usage
client/exec-api echo hello

# JSON envelope mode (structured output, always exits 0)
client/exec-api --json ls -la

# Retry on transport errors
client/exec-api --json --retry 3 echo hello

# Retry on any error (transport + nonzero exit)
client/exec-api --json --retry 3 --retry-on any mycommand

# Pipe stdin
echo "input" | client/exec-api --json cat

# Upload files
client/exec-api --json --file ./data.csv mycommand @file:data.csv

# Structured JSON request on stdin (the agent-friendly path)
echo '{"command":"echo","argv":["hello"]}' | client/exec-api --json-request

# Structured JSON request from a file (useful when stdin is unavailable)
client/exec-api --json-request-file request.json
```

### JSON Envelope

In `--json` mode, output is a JSON object — the same shape every time, success or failure, so the harness has exactly one parser to write:

```json
{
  "ok": true,
  "error_type": null,
  "transport": "exec-api",
  "host": "127.0.0.1:8019",
  "command": ["echo", "hello"],
  "exit_code": 0,
  "stdout": "hello\n",
  "stderr": "",
  "timing_total_ms": 45,
  "timing_exec_ms": 12,
  "attempts": 1
}
```

`error_type` is one of: `null` (success), `"transport"` (network), `"request"` (HTTP error), `"command"` (nonzero exit), `"usage"` (client error).

## API

### `POST /run`

**Request:**

```json
{
  "command": "echo",
  "args": ["hello", "world"],
  "stdin_text": "optional input",
  "stdin_encoding": "utf-8",
  "files": [
    {"name": "data.csv", "content_base64": "..."}
  ]
}
```

**Response:**

```json
{
  "stdout": "hello world\n",
  "stderr": "",
  "code": 0,
  "exec_ms": 12
}
```

All fields except `command` are optional. Files are staged in a per-request temp directory and cleaned up after execution. Use `@file:<name>` or `@file:<index>` placeholders in `args` to reference uploaded files, or they are appended automatically.
