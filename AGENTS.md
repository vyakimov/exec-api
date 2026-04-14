# Exec API Instructions

## Purpose

This repo contains a minimal HTTP server that executes allowlisted commands with bearer-token auth, plus a stdlib-only Python client.

- `server.py` — FastAPI app that runs allowlisted commands. Returns `{stdout, stderr, code, exec_ms}`.
- `client/run.py` — stdlib-only CLI client with JSON envelope mode, retry with exponential backoff, stdin forwarding, and file uploads.
- `client/exec-api` — shell wrapper for `run.py`.

## Configuration

- `allowlist.txt` — one command name per line, `#` comments. Loaded at startup into a frozen set. Gitignored — copy from `allowlist.txt.example` to get started.
- `command-paths.json` — optional `{"command": "/absolute/path"}` map for commands that should not be resolved from `$PATH`. Gitignored — copy from `command-paths.json.example`.
- `EXEC_API_TOKEN` — required env var for the server. Bearer token for authentication.
- `EXEC_API_READ_PREFIXES` — optional colon-separated list of absolute path prefixes that `/read-file` is allowed to read under. Defaults to `$HOME`. Resolved at startup with symlinks followed.

## Core Security Properties

Any change that weakens these properties is security-sensitive:

- Never use shell execution. Commands run via `subprocess`/exec with an argument list.
- The allowlist is frozen at startup and is not runtime-configurable.
- Bearer-token auth with constant-time comparison.
- 30-second command timeout.
- Optional UTF-8 stdin forwarding with a 256 KiB limit.
- File uploads use strict basename-only validation, per-request temp directories, size limits, and cleanup after execution.
- `/read-file` resolves the requested path (following symlinks) and rejects anything not under `EXEC_API_READ_PREFIXES` (defaults to `$HOME`). Size is capped at 10 MiB.
- `exec_ms` (server-side execution time) is part of the response contract.

## Change Guidelines

Prefer small, explicit changes. Preserve the service's simplicity.

- Do not make the allowlist runtime-configurable unless explicitly requested.
- Do not add `shell=True`, string command interpolation, or any quoting-based execution path.
- Keep the request and response shape stable unless asked for an API change.
- If adding a new allowed command, add it to `allowlist.txt`.
- If changing stdin behavior, preserve the explicit encoding check and size cap.
- If changing file upload behavior, preserve basename-only validation, request isolation, and cleanup guarantees.
- If changing timeouts, call out the operational tradeoff because clients depend on predictable request latency.

## Verification

- Syntax check: `python3 -m py_compile server.py`
- Syntax check: `python3 -m py_compile client/run.py`
- Run locally: `EXEC_API_TOKEN=test uvicorn server:app --host 127.0.0.1 --port 8019`
