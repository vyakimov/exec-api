#!/usr/bin/env python3
"""CLI client for exec-api. No dependencies beyond stdlib."""

import base64
import json
import os
import random
import sys
import time
import urllib.request
import urllib.error

HOST = os.environ.get("EXEC_API_HOST", "127.0.0.1:8019")
TOKEN = os.environ.get("EXEC_API_TOKEN", "")

TRANSPORT = "exec-api"
MAX_RETRIES = 5
RETRY_ON_CHOICES = ("transport", "any")
STDIN_MODE_CHOICES = ("auto", "always", "never")
MAX_FILE_BYTES = 5 * 1024 * 1024


def build_envelope(*, ok, error_type=None, command=None, exit_code=None,
                   stdout=None, stderr=None, detail=None,
                   timing_total_ms=None, timing_exec_ms=None):
    env = {
        "ok": ok,
        "error_type": error_type,
        "transport": TRANSPORT,
        "host": HOST,
        "command": command,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "timing_total_ms": timing_total_ms,
        "timing_exec_ms": timing_exec_ms,
    }
    if detail is not None:
        env["detail"] = detail
    return env


def do_request(url, payload, command, args):
    """Execute one HTTP request. Returns (envelope_dict, raw_result_or_None)."""
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
        method="POST",
    )

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=35) as resp:
            result = json.loads(resp.read())
        elapsed = round((time.monotonic() - t0) * 1000)
    except urllib.error.HTTPError as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        body = e.read().decode(errors="replace")
        return build_envelope(
            ok=False,
            error_type="request",
            command=[command] + args,
            detail=f"HTTP {e.code}: {body}",
            timing_total_ms=elapsed,
        ), None
    except (urllib.error.URLError, OSError) as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        reason = getattr(e, "reason", str(e))
        return build_envelope(
            ok=False,
            error_type="transport",
            command=[command] + args,
            detail=f"cannot reach exec API at {HOST}: {reason}",
            timing_total_ms=elapsed,
        ), None

    cmd_ok = result.get("code", 0) == 0
    return build_envelope(
        ok=cmd_ok,
        error_type=None if cmd_ok else "command",
        command=[command] + args,
        exit_code=result.get("code", 0),
        stdout=result.get("stdout", ""),
        stderr=result.get("stderr", ""),
        timing_total_ms=elapsed,
        timing_exec_ms=result.get("exec_ms"),
    ), result


def should_retry(envelope, retry_on):
    """Return True if this envelope's error type is retriable."""
    et = envelope.get("error_type")
    if et == "transport":
        return True
    if retry_on == "any" and et == "command":
        return True
    return False


def backoff_sleep(attempt):
    """Exponential backoff with ±25% jitter. attempt is 0-indexed."""
    base = min(2 ** attempt, 8)
    jitter = base * random.uniform(-0.25, 0.25)
    time.sleep(base + jitter)


def emit_error(json_mode, msg):
    if json_mode:
        print(json.dumps(build_envelope(ok=False, error_type="usage", detail=msg)))
        sys.exit(0)
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def load_input_file(json_mode, file_path):
    if not os.path.isfile(file_path):
        emit_error(json_mode, f"file not found: {file_path}")
    try:
        with open(file_path, "rb") as fh:
            content = fh.read()
    except OSError as exc:
        emit_error(json_mode, f"failed to read file '{file_path}': {exc}")
    if len(content) > MAX_FILE_BYTES:
        emit_error(
            json_mode,
            f"file '{file_path}' too large ({len(content)} bytes, max {MAX_FILE_BYTES})",
        )
    return {
        "name": os.path.basename(file_path),
        "content_base64": base64.b64encode(content).decode("ascii"),
    }


def parse_json_request(json_mode):
    """Read a JSON request object from stdin and return (command, args, body)."""
    raw = sys.stdin.read()
    if not raw.strip():
        emit_error(json_mode, "--json-request requires a JSON object on stdin")
    try:
        req = json.loads(raw)
    except json.JSONDecodeError as exc:
        emit_error(json_mode, f"--json-request: invalid JSON: {exc}")
    if not isinstance(req, dict):
        emit_error(json_mode, "--json-request: expected a JSON object")

    command = req.get("command")
    if not command or not isinstance(command, str):
        emit_error(json_mode, "--json-request: 'command' is required (string)")

    argv_field = req.get("argv", [])
    if not isinstance(argv_field, list) or not all(isinstance(a, str) for a in argv_field):
        emit_error(json_mode, "--json-request: 'argv' must be an array of strings")

    body: dict = {"command": command, "args": argv_field}

    stdin_text = req.get("stdin")
    if stdin_text is not None:
        if not isinstance(stdin_text, str):
            emit_error(json_mode, "--json-request: 'stdin' must be a string")
        if stdin_text:
            body["stdin_text"] = stdin_text
            body["stdin_encoding"] = "utf-8"

    files = req.get("files")
    if files is not None:
        if not isinstance(files, list):
            emit_error(json_mode, "--json-request: 'files' must be an array")
        for i, f in enumerate(files):
            if not isinstance(f, dict):
                emit_error(json_mode, f"--json-request: files[{i}] must be an object")
            if "name" not in f or "content_base64" not in f:
                emit_error(json_mode, f"--json-request: files[{i}] requires 'name' and 'content_base64'")
        body["files"] = files

    return command, argv_field, body


def main():
    # Parse wrapper flags before the command name
    argv = sys.argv[1:]
    json_mode = False
    json_request = False
    retries = 0
    retry_on = "transport"
    stdin_mode = "auto"
    files = []

    while argv and argv[0].startswith("--"):
        flag = argv.pop(0)
        if flag == "--json":
            json_mode = True
        elif flag == "--json-request":
            json_request = True
            json_mode = True  # --json-request implies --json
        elif flag == "--retry":
            if not argv:
                emit_error(json_mode, "--retry requires a number")
            try:
                retries = int(argv.pop(0))
            except ValueError:
                emit_error(json_mode, "--retry requires a number")
            if retries < 0 or retries > MAX_RETRIES:
                emit_error(json_mode, f"--retry must be 0-{MAX_RETRIES}")
        elif flag == "--retry-on":
            if not argv:
                emit_error(json_mode, f"--retry-on requires one of: {', '.join(RETRY_ON_CHOICES)}")
            retry_on = argv.pop(0)
            if retry_on not in RETRY_ON_CHOICES:
                emit_error(json_mode, f"--retry-on must be one of: {', '.join(RETRY_ON_CHOICES)}")
        elif flag == "--stdin":
            if not argv:
                emit_error(json_mode, f"--stdin requires one of: {', '.join(STDIN_MODE_CHOICES)}")
            stdin_mode = argv.pop(0)
            if stdin_mode not in STDIN_MODE_CHOICES:
                emit_error(json_mode, f"--stdin must be one of: {', '.join(STDIN_MODE_CHOICES)}")
        elif flag == "--no-stdin":
            stdin_mode = "never"
        elif flag == "--file":
            if not argv:
                emit_error(json_mode, "--file requires a local path")
            files.append(load_input_file(json_mode, argv.pop(0)))
        elif flag == "--":
            break
        else:
            emit_error(json_mode, f"unknown flag: {flag}")

    if json_request:
        # --json-request mode: read structured JSON from stdin
        if argv:
            emit_error(json_mode, "--json-request cannot be combined with positional command/args")
        if files:
            emit_error(json_mode, "--json-request cannot be combined with --file")
        if stdin_mode != "auto":
            emit_error(json_mode, "--json-request cannot be combined with --stdin/--no-stdin")
        command, args, body = parse_json_request(json_mode)
    else:
        if len(argv) < 1:
            emit_error(
                json_mode,
                "usage: run.py [--json] [--json-request] [--retry N] "
                "[--retry-on transport|any] [--stdin auto|always|never|--no-stdin] "
                "[--file PATH ...] <command> [args...]",
            )
        command = argv[0]
        args = argv[1:]

    if not TOKEN:
        emit_error(json_mode, "EXEC_API_TOKEN not set")

    if not json_request:
        # CLI mode: build the request body from flags and positional args.
        body: dict = {"command": command, "args": args}
        should_read_stdin = stdin_mode == "always" or (
            stdin_mode == "auto" and not sys.stdin.isatty()
        )
        if should_read_stdin:
            stdin_text = sys.stdin.read()
            if stdin_text:
                body["stdin_text"] = stdin_text
                body["stdin_encoding"] = "utf-8"
        if files:
            body["files"] = files

    url = f"http://{HOST}/run"
    payload = json.dumps(body).encode()

    max_attempts = 1 + retries
    envelope = None
    result = None

    for attempt in range(max_attempts):
        envelope, result = do_request(url, payload, command, args)

        if envelope["ok"] or attempt == max_attempts - 1:
            break

        if not should_retry(envelope, retry_on):
            break

        if not json_mode:
            print(
                f"retry {attempt + 1}/{retries}: {envelope.get('error_type')} error, retrying...",
                file=sys.stderr,
            )
        backoff_sleep(attempt)

    if json_mode:
        envelope["attempts"] = attempt + 1
        print(json.dumps(envelope))
        sys.exit(0)

    # Raw mode: preserve original behavior
    if result is None:
        print(f"error: {envelope.get('detail', 'unknown error')}", file=sys.stderr)
        sys.exit(1)

    if result.get("stdout"):
        print(result["stdout"], end="")
    if result.get("stderr"):
        print(result["stderr"], end="", file=sys.stderr)

    sys.exit(result.get("code", 0))


if __name__ == "__main__":
    main()
