# Exec API Instructions

## Purpose

This repo contains a minimal HTTP server that executes allowlisted commands with bearer-token auth, plus a stdlib-only Python client.

- `server.py` — FastAPI app. Policy-checked filesystem operations (`/read-file`, `/write-file`, `/copy-uploaded-file`, `/search-files`, `/list-dir`, `/delete-file`, `/move-file`) plus an allowlisted-command runner (`/run`) and discovery endpoints (`/capabilities`, `/healthz`). Built by `create_app(config, environ)`; config-derived state lives on `app.state.exec` (an `AppState`), and the module-level `app` is the instance uvicorn serves. Tests build independent apps via the factory — see `conftest.py`.
- `client/run.py` — stdlib-only CLI client with JSON envelope mode, retry with exponential backoff, stdin forwarding, file uploads, and flags for each filesystem operation.
- `client/exec-api` — shell wrapper for `run.py`.

## Configuration

- `config.yaml` — the security boundary. Top-level sections: `filesystem` (read/write prefixes, size limits, `allow_symlink_final_target`), `operations` (per-endpoint on/off toggles), and `commands` (the `/run` allowlist with optional `executable` paths). Resolved at startup; the server refuses to start if missing. Gitignored — copy from `config.yaml.example`.
- `auth` / `policies` — optional. Maps bearer tokens (each resolved from its own env var) to named principals, and principals to policies. A policy either `inherit_default`s the top-level blocks or defines its own narrower `filesystem` / `operations` / `commands`. A policy's `commands` references names from the top-level registry and may add per-command `env` overrides injected into that command's process. **Backward-compatible:** if `auth:` is absent, the single `EXEC_API_TOKEN` gets the top-level policy as an implicit `owner` principal — identical to the old single-token behavior.
- `EXEC_API_TOKEN` (and any additional per-principal token env vars) — bearer tokens for authentication. Secrets live in the environment / `.env`, never in `config.yaml`.

## Core Security Properties

Any change that weakens these properties is security-sensitive:

- **Operations are the boundary.** Every filesystem touch goes through `can_read` / `can_write` / `can_list`, which resolve the path and check it against the configured prefixes. Do not add a raw file utility (`cat`, `grep`, `rg`, `find`, `ls`, …) to the command allowlist — that bypasses the prefixes. Use or extend an operation instead.
- **Hard denylist.** `DENIED_COMMANDS` (osascript, ssh, scp, rsync, interpreters, `find`, `xargs`, `make`, `git`, …) are refused at load even if `config.yaml` marks them `allowed: true`. Never remove an entry to make something runnable; sandbox instead.
- Never use shell execution. Commands run via `subprocess`/exec with an argument list. `search-files` passes the query positionally after `--`.
- Bearer-token auth with constant-time comparison. With multiple principals the presented token is compared against every configured token without early-exit, so a match leaks neither which principal nor whether one matched.
- **Per-principal policy.** Every endpoint resolves the caller to a `Principal` via `_check_auth` and enforces *that principal's* `operations` / prefixes / command set — never the globals. New endpoints must thread the principal through their policy checks. Policy decisions are logged with the principal name.
- **Command env injection is an allowlist, not arg filtering.** `/run` merges `os.environ` with the principal's per-command `env` overrides. exec-api can scope *who* calls a command and inject env (e.g. `YNAB_PROFILE`), but args pass through unfiltered — a CLI that honors an overriding flag (`--profile`) must enforce identity itself. Never try to police identity by inspecting argv.
- 30-second command/search timeout.
- Optional UTF-8 stdin forwarding with a 256 KiB limit.
- File uploads use strict basename-only validation, per-request temp directories, size limits, and cleanup after execution.
- Reads/list/search resolve paths (following symlinks) and reject anything not under `read_prefixes`. Writes resolve the deepest existing ancestor, require the destination under `write_prefixes`, reject a symlinked final target by default, and write atomically. Sizes capped by `max_read_bytes` / `max_write_bytes`.
- `exec_ms` (server-side execution time) is part of every response contract.
- Policy decisions are logged (operation, original path, resolved path, allow/deny, bytes). **Never log file contents.**

## Change Guidelines

Prefer small, explicit changes. Preserve the service's simplicity.

- Do not add `shell=True`, string command interpolation, or any quoting-based execution path.
- Keep request/response shapes stable unless asked for an API change.
- Route new filesystem capabilities through the policy functions; do not bypass them or expose arbitrary argv to file tools.
- If adding a new allowed command, add it under `commands` in `config.yaml` (and `config.yaml.example`). Confirm it is not on the hard denylist.
- If changing stdin behavior, preserve the explicit encoding check and size cap.
- If changing file upload/staging behavior, preserve basename-only validation, request isolation, and cleanup guarantees.
- If changing timeouts, call out the operational tradeoff because clients depend on predictable request latency.

## Verification

- Lint: `ruff check .` (configured in `pyproject.toml`; subsumes a syntax check)
- Tests: `pip install -r requirements-dev.txt && python3 -m pytest` (covers auth, per-principal policy, command allowlisting, env injection, and startup-fatal misconfigs).
- CI (`.github/workflows/ci.yml`) runs ruff + pytest with a coverage gate on every push.
- Run locally for a quick check (needs a `config.yaml`): `EXEC_API_TOKEN=test uvicorn server:app --host 127.0.0.1 --port 8019`
