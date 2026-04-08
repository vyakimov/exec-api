# exec-api

A minimal HTTP server that executes allowlisted commands with bearer-token auth. Includes a stdlib-only Python client.

## Security Model

- **Frozen allowlist** — only commands listed in `allowlist.txt` can run. The set is loaded once at startup.
- **No shell execution** — commands run via `subprocess.exec` with an argument list, never through a shell.
- **Bearer-token auth** — every request must include a valid token (constant-time comparison).
- **Timeouts** — 30-second limit per command.
- **File uploads** — basename-only validation, size limits (5 MiB per file, 10 MiB total), per-request temp directories with guaranteed cleanup.
- **Stdin limits** — optional UTF-8 stdin forwarding capped at 256 KiB.

## Quick Start

```bash
pip install -r requirements.txt

# Configure the allowlist (edit to suit your deployment)
cp allowlist.txt.example allowlist.txt
# Edit allowlist.txt as needed

# Optional: map commands to specific paths instead of $PATH lookup
cp command-paths.json.example command-paths.json
# Edit command-paths.json as needed

# Start the server
EXEC_API_TOKEN=your-secret-token uvicorn server:app --host 127.0.0.1 --port 8019
```

## Configuration

| File / Env Var | Purpose |
|---|---|
| `allowlist.txt` | One command name per line. `#` comments and blank lines are ignored. Gitignored — copy from `allowlist.txt.example` to get started. |
| `command-paths.json` | Optional `{"command": "/path"}` map for commands that should not be resolved from `$PATH`. Gitignored — copy from `command-paths.json.example`. |
| `EXEC_API_TOKEN` | Required. Bearer token for server authentication. |

## Client

The `client/` directory contains a stdlib-only Python client (no dependencies beyond Python 3).

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

# Structured JSON request on stdin
echo '{"command":"echo","argv":["hello"]}' | client/exec-api --json-request
```

### JSON Envelope

In `--json` mode, output is a JSON object:

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
