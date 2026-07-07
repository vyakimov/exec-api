# exec-api

**Run allowlisted shell commands on a remote host, over HTTP, with JSON in and JSON out.**

Built for LLM harnesses. Your agent runs on one machine; the tools it needs (compilers, CLIs, scripts, build systems) live on another. exec-api lets the harness reach across that gap safely: every invocation is a single JSON request, every result is a structured JSON envelope — easy to parse, easy to log, impossible to confuse with normal shell output.

## Why use this

- **Remote execution for agents.** Run an LLM loop in one environment and execute its commands in another (different OS, different network, dedicated sandbox VM) without giving it shell access.
- **JSON in, JSON out.** Commands are wrapped in JSON so a model can construct them reliably and a harness can parse the result without regex-scraping stdout/stderr.
- **Safe by default.** Frozen allowlist, no shell interpolation, bearer-token auth, timeouts, file-size caps. The agent can only do what you've explicitly permitted.
- **Tiny.** A single FastAPI server and a stdlib-only Python client. No queue, no database, no plugin system.

## Security Model

**Operations are the boundary.** Filesystem access goes through policy-checked
operations — `/read-file`, `/write-file`, `/copy-uploaded-file`, `/search-files`,
`/list-dir` — each validated against the prefixes in `config.yaml`. The binary
allowlist (`/run`) is only a last line of defense.

- **Policy-checked filesystem ops** — every read/write/list/search resolves the
  path (following symlinks) and checks it against `read_prefixes` / `write_prefixes`.
  Raw file tools (`cat`, `grep`, `rg`, `fd`, `find`, `ls`) are **not** allowlisted —
  use the operations instead, so the prefixes actually mean something.
- **Writes are safe-by-default** — atomic create-or-replace, no-clobber `create`
  mode, size caps, and a symlinked final target is rejected unless
  `allow_symlink_final_target` is set.
- **Binary allowlist** — only commands marked `allowed: true` in `config.yaml` run.
- **Hard denylist** — code-execution-capable binaries (osascript, ssh, scp, rsync,
  interpreters, `find`, `xargs`, `make`, `git`, …) are refused at load even if a
  config marks them allowed. They can never run.
- **No shell execution** — `subprocess.exec` with an argv list. No `sh -c`, no
  interpolation, no injection surface. `search-files` passes the query positionally
  after `--`.
- **Bearer-token auth** — every request requires a token (constant-time comparison).
  Multiple tokens can map to different **principals**, each with its own policy
  (filesystem prefixes, operation toggles, command set) — see [Per-user policies](#per-user-policies).
- **Timeouts** — configurable seconds per command/search (`command_timeout`,
  default 30), optionally narrowed per principal (`limits:`).
- **Request size cap** — bodies larger than the biggest configured write/upload
  payload (base64-inflated, plus slack) are rejected up front with 413.
- **Transport** — the server speaks plain HTTP; the bearer token and all file
  contents are visible on the wire. Bind to `127.0.0.1` and reach it through an
  SSH tunnel, Tailscale, or a TLS-terminating reverse proxy — never expose the
  port directly on an untrusted network. The client accepts a scheme in
  `EXEC_API_HOST` (e.g. `https://exec.example.com`) for the proxy case.
- **File uploads** — basename-only validation, 5 MiB per file, 10 MiB total,
  per-request temp dir with guaranteed cleanup.
- **Stdin limits** — optional UTF-8 stdin forwarding, capped at 256 KiB.

## Allowlist hazards

The allowlist only checks the **top-level binary**. Arguments are passed through unfiltered, and there is no shell, but a binary that can itself spawn other binaries defeats the allowlist entirely. Treat the allowlist as "what this binary can do," not "what command runs."

A built-in **hard denylist** refuses these at load even if `config.yaml` marks them
`allowed: true`, but the categories are worth knowing — do not rely on the denylist
being exhaustive:

- `find`, `fd` — `-exec` / `-x` run any binary
- `xargs`, `env`, `nice`, `nohup`, `time`, `timeout`, `parallel` — run a named program
- `awk` (`system()`), GNU `sed` (`e` command), `make` — shell out
- `git` — `-c core.sshCommand=…`, aliases, and hooks execute code
- `python`, `node`, `perl`, `ruby`, `bash`, `sh` and other interpreters
- `vim`, `less`, `man`, `gdb` — `!cmd` shell escapes
- `ssh` (`ProxyCommand`), `tar` (`--use-compress-program`), `rsync` (`-e`), `scp`
- `osascript` — arbitrary macOS automation

If you need one of these, run exec-api in a dedicated sandbox VM where breaking out of the allowlist has no consequences — the allowlist alone will not contain it.

The filesystem prefixes deserve the same scrutiny: anything under `read_prefixes` is readable, and anything under `write_prefixes` is writable, by anyone with the token. Keep them narrow; avoid broad ones like `$HOME`, which expose `~/.ssh`, `~/.aws`, browser profiles, and keychains.

The same "args are unfiltered" rule limits what per-command **env injection** can enforce. A policy can inject env into a command's process (e.g. `YNAB_PROFILE=emma`) to scope *who* is calling, but it cannot stop the caller from passing an overriding flag (`--profile victor`, `--profile=victor`, `-p victor`, …). exec-api owns *who is calling and what env they get*; the **CLI must own its own identity** — prefer/lock to the injected env var, refuse or restrict overriding flags, and echo the effective identity in its output. Do not rely on exec-api to police identity by inspecting argv.

## Quick Start

```bash
pip install -r requirements.txt

# Define the policy: filesystem prefixes, operation toggles, command allowlist
cp config.yaml.example config.yaml
# Edit config.yaml

# Start the server (EXEC_API_TOKEN is the only required env var)
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
cp config.yaml.example config.yaml   # edit: prefixes, operations, commands
cp .env.example .env                 # edit: set EXEC_API_TOKEN and any CLI secrets

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

### Linux systemd service

`install-systemd.sh` mirrors the launchd installer as a systemd **user** unit,
with the same flags and `.env` handling (loaded via `EnvironmentFile`):

```bash
./install-systemd.sh --host 127.0.0.1 --port 8019
systemctl --user restart exec-api      # after editing .env
loginctl enable-linger $USER           # keep it running after logout
```

## Configuration

| File / Env Var | Purpose |
|---|---|
| `config.yaml` | Filesystem prefixes/limits, operation toggles, and the command allowlist (with optional `executable` paths). The security boundary. Gitignored — copy from `config.yaml.example`. |
| `.env` | `KEY=VALUE` pairs passed to the service via `install-launchd.sh`. Must contain `EXEC_API_TOKEN`; holds CLI secrets. Gitignored — copy from `.env.example`. |

### `config.yaml`

```yaml
filesystem:
  read_prefixes:  [/Users/vy/Desktop, /Users/vy/Downloads]   # read/list/search
  write_prefixes: [/Users/vy/Downloads, /tmp]                # write/copy
  max_read_bytes: 10485760
  max_write_bytes: 10485760
  allow_symlink_final_target: false   # reject writing through a symlink

operations:                            # toggle endpoints; disabled -> 404
  read_file: true
  write_file: true
  copy_uploaded_file: true
  search_files: true
  list_dir: true

commands:                              # /run allowlist (last line of defense)
  bearctl: { allowed: true, executable: /opt/homebrew/bin/bearctl }
  ping:    { allowed: true }
  osascript: { allowed: false }        # also blocked by the hard denylist
```

### Per-user policies

By default exec-api runs in **single-token mode**: the one token in `EXEC_API_TOKEN`
gets the policy defined by the top-level `filesystem` / `operations` / `commands`
blocks above. Anyone with that token has full access.

Add an optional `auth` / `policies` section to map **different tokens to different
policies** — e.g. a partner's agent on another host that can run a couple of CLIs
but touch no files. It is fully backward-compatible: **if `auth:` is absent, nothing
changes.**

```yaml
auth:
  tokens:
    victor: { env: EXEC_API_TOKEN,      policy: owner }    # each token from its own env var
    emma:   { env: EXEC_API_TOKEN_EMMA, policy: partner }

policies:
  owner:
    filesystem: inherit_default        # reuse the top-level blocks
    operations: inherit_default
    commands: inherit_default
  partner:
    filesystem:                        # no shared paths -> no filesystem access
      read_prefixes: []
      write_prefixes: []
    operations: {}                     # every read/write/list/search op -> 404
    commands:                          # command surfaces only, by name
      inventory: {}
      huckctl: {}
      ynab: { env: { YNAB_PROFILE: emma } }   # per-command env injection
```

- **`tokens`** — each entry names a principal and points at the env var holding its
  bearer token (kept out of `config.yaml`, same as `EXEC_API_TOKEN`). A
  configured-but-empty token, or two principals sharing a token value, is fatal at
  startup.
- **`policies`** — each field is either `inherit_default` (reuse the top-level block)
  or an explicit narrower value. `commands` references **names from the top-level
  `commands` registry** (executables and the hard denylist are still resolved there,
  once); a policy referencing an unknown or unresolved command is fatal at startup.
- **Per-policy `limits`** — optional `max_read_bytes` / `max_write_bytes` /
  `command_timeout`, each defaulting to the top-level value, so a low-trust
  principal can get smaller caps and a shorter timeout.
- **Per-command `env`** is merged over the server environment for that command only.
  See the [identity caveat](#allowlist-hazards): this scopes *who is calling*, but the
  CLI must enforce its own identity — args are not filtered.
- **Fail-closed.** Giving a principal all operations off makes every filesystem
  endpoint 404. And a policy that enables an operation while leaving the matching
  prefixes empty is rejected at **startup** (the server refuses to run), so there is
  no way to end up with an enabled-but-unbounded operation.

Every policy decision and `/run` invocation is logged with the principal name for an
audit trail.

## Client

The `client/` directory contains a stdlib-only Python client (Python 3, no dependencies). Drop it onto the harness host and call it directly.

### Environment Variables

| Env Var | Default | Purpose |
|---|---|---|
| `EXEC_API_HOST` | `127.0.0.1:8019` | Server `host:port`, or a full base URL with scheme (`https://exec.example.com`) when behind a TLS proxy |
| `EXEC_API_TOKEN` | (required) | Bearer token |

### Usage

```bash
# Basic usage
client/exec-api echo hello

# JSON envelope mode (structured output, always exits 0)
client/exec-api --json ls -la

# Retry on transport errors
client/exec-api --json --retry 3 echo hello

# Retry on any error (transport + nonzero exit).
# CAUTION: /run is not idempotent — a command that timed out or failed midway may
# have had side effects, and --retry-on any will run it again. Use only for
# commands that are safe to repeat.
client/exec-api --json --retry 3 --retry-on any mycommand

# Pipe stdin
echo "input" | client/exec-api --json cat

# Upload files
client/exec-api --json --file ./data.csv mycommand @file:data.csv

# Filesystem operations
client/exec-api --read-file /allowed/path/file.txt > local.txt
echo "contents" | client/exec-api --write-file /allowed/path/out.txt   # create (default)
echo "more"     | client/exec-api --write-file /allowed/path/out.txt --mode overwrite
client/exec-api --copy-file ./local.bin /allowed/path/remote.bin
client/exec-api --search /allowed/path "needle" --ignore-case
client/exec-api --list-dir /allowed/path
client/exec-api --delete-file /allowed/path/old.txt
client/exec-api --move-file /allowed/path/a.txt /allowed/path/b.txt

# What am I allowed to do? (this token's policy view)
client/exec-api --capabilities

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

### `POST /read-file`

Returns the contents of a single file as base64. Intended for pulling remote artifacts (images, PDFs, logs) back to the caller.

**Request:**

```json
{"path": "/Users/someone/screenshot.png"}
```

**Response:**

```json
{
  "name": "screenshot.png",
  "path": "/Users/someone/screenshot.png",
  "size": 48213,
  "mime": "image/png",
  "content_base64": "...",
  "exec_ms": 3
}
```

The path is resolved (symlinks followed) and must fall under a `read_prefixes`
entry in `config.yaml`. Optional `offset` / `length` fields read a byte range —
the response carries `total_size`, `offset`, and `eof` so a caller can page
through a large file. Reads returning more than `max_read_bytes` are rejected
with HTTP 413.

### `POST /write-file`

Writes a small file atomically under a `write_prefixes` entry.

**Request:**

```json
{
  "path": "/Users/vy/Downloads/foo.txt",
  "content_base64": "...",
  "mode": "create",
  "mkdirs": false,
  "expected_sha256": "optional"
}
```

`mode` is `create` (default; fails with 409 if the file exists), `overwrite`
(atomic replace), or `append`. The destination is canonicalized (the deepest
existing ancestor is symlink-resolved); a symlinked final target is rejected
unless `allow_symlink_final_target` is set. Content over `max_write_bytes` → 413.
If `expected_sha256` is supplied and does not match the content hash → 400.

**Response:** `{"path", "size", "sha256", "created", "exec_ms"}`.

### `POST /copy-uploaded-file`

Stages an uploaded file and places it at a destination under `write_prefixes`,
using the same write rules as `/write-file`.

**Request:**

```json
{
  "file": "@file:0",
  "dest": "/Users/vy/Downloads/foo.bin",
  "mode": "create",
  "files": [{"name": "foo.bin", "content_base64": "..."}]
}
```

`file` references one staged upload by `@file:<index>` / `@file:<name>` (or bare
`0` / name). **Response:** `{"path", "size", "sha256", "created", "exec_ms"}`.

### `POST /search-files`

Searches under a `read_prefixes` directory (uses `rg` internally; falls back to a
Python walk). Arbitrary `rg` flags are **not** exposed. Both engines behave the
same way: hidden and gitignored files are searched, symlinks are never followed,
and `glob` patterns match file names (not full paths).

**Request:**

```json
{"root": "/allowed/path", "query": "needle", "ignore_case": false, "fixed_strings": false, "glob": "*.py", "max_results": 1000}
```

**Response:** `{"root", "matches": [{"path", "line", "text"}], "truncated", "engine", "exec_ms"}`.

### `POST /list-dir`

Lists a single directory (non-recursive) under a `read_prefixes` entry.

**Request:** `{"path": "/allowed/path"}`

**Response:** `{"path", "entries": [{"name", "type", "size", "mtime"}], "truncated", "exec_ms"}`.

### `POST /delete-file`

Deletes a single file (or symlink — the link itself, never its target) under a
`write_prefixes` entry. Directories are refused.

**Request:** `{"path": "/allowed/path/old.txt"}` — **Response:** `{"path", "exec_ms"}`.

### `POST /move-file`

Renames a file; both `src` and `dest` must be under `write_prefixes`, on the
same filesystem. `mode` is `create` (default; 409 if `dest` exists, atomically)
or `overwrite`. A symlink `src` is refused.

**Request:** `{"src": "...", "dest": "...", "mode": "create", "mkdirs": false}` —
**Response:** `{"src", "path", "exec_ms"}`.

### `GET /capabilities`

Returns the calling principal's own policy view — enabled operations, prefixes,
command names (with effective timeout/cwd), and limits — so an agent can
construct valid requests instead of discovering the policy by trial and 403.

### `GET /healthz`

Unauthenticated liveness probe; returns `{"status": "ok"}` and nothing else.
