#!/usr/bin/env python3
"""CLI client for exec-api. No dependencies beyond stdlib."""

import base64
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

HOST = os.environ.get("EXEC_API_HOST", "127.0.0.1:8019")
# EXEC_API_HOST may carry a scheme (e.g. https://exec.example.com behind a
# TLS-terminating proxy); bare host:port keeps the historical http:// default.
BASE_URL = HOST.rstrip("/") if "://" in HOST else f"http://{HOST}"
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


def do_read_file_request(url, payload, path):
    """Execute one /read-file request. Returns (envelope_dict, raw_result_or_None)."""
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
            command=["read-file", path],
            detail=f"HTTP {e.code}: {body}",
            timing_total_ms=elapsed,
        ), None
    except (urllib.error.URLError, OSError) as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        reason = getattr(e, "reason", str(e))
        return build_envelope(
            ok=False,
            error_type="transport",
            command=["read-file", path],
            detail=f"cannot reach exec API at {HOST}: {reason}",
            timing_total_ms=elapsed,
        ), None

    envelope = build_envelope(
        ok=True,
        command=["read-file", path],
        exit_code=0,
        timing_total_ms=elapsed,
        timing_exec_ms=result.get("exec_ms"),
    )
    envelope["file"] = {
        "name": result.get("name"),
        "path": result.get("path"),
        "size": result.get("size"),
        "mime": result.get("mime"),
        "content_base64": result.get("content_base64"),
    }
    return envelope, result


def do_op_request(url, payload, label):
    """Execute one request to a filesystem-operation endpoint.

    Returns (envelope_dict, raw_result_or_None). The raw server response is
    attached to the envelope under "result" on success.
    """
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
            command=label,
            detail=f"HTTP {e.code}: {body}",
            timing_total_ms=elapsed,
        ), None
    except (urllib.error.URLError, OSError) as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        reason = getattr(e, "reason", str(e))
        return build_envelope(
            ok=False,
            error_type="transport",
            command=label,
            detail=f"cannot reach exec API at {HOST}: {reason}",
            timing_total_ms=elapsed,
        ), None

    envelope = build_envelope(
        ok=True,
        command=label,
        exit_code=0,
        timing_total_ms=elapsed,
        timing_exec_ms=result.get("exec_ms"),
    )
    envelope["result"] = result
    return envelope, result


def should_retry(envelope, retry_on):
    """Return True if this envelope's error type is retriable."""
    et = envelope.get("error_type")
    if et == "transport":
        return True
    return retry_on == "any" and et == "command"


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


def parse_json_request(json_mode, raw=None):
    """Parse a JSON request and return (command, args, body).

    If raw is None, reads from stdin.
    """
    if raw is None:
        raw = sys.stdin.read()
    if not raw.strip():
        emit_error(json_mode, "--json-request requires a JSON object")
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
                emit_error(
                    json_mode,
                    f"--json-request: files[{i}] requires 'name' and 'content_base64'",
                )
        body["files"] = files

    return command, argv_field, body


def run_with_retries(request_fn, retries, retry_on, json_mode):
    """Call request_fn() up to 1+retries times with backoff. Returns (envelope, result)."""
    max_attempts = 1 + retries
    envelope = None
    result = None
    attempt = 0
    for attempt in range(max_attempts):
        envelope, result = request_fn()
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
    envelope["attempts"] = attempt + 1
    return envelope, result


def main():
    # Parse wrapper flags before the command name
    argv = sys.argv[1:]
    json_mode = False
    json_request = False
    json_request_file = None
    retries = 0
    retry_on = "transport"
    stdin_mode = "auto"
    files = []
    read_file_path = None
    write_file_dest = None
    copy_local = None
    copy_dest = None
    search_root = None
    search_query = None
    list_dir_path = None
    op_mode = "create"
    mkdirs = False
    glob = None
    ignore_case = False
    fixed_strings = False

    while argv and argv[0].startswith("--"):
        flag = argv.pop(0)
        if flag == "--json":
            json_mode = True
        elif flag == "--json-request":
            json_request = True
            json_mode = True  # --json-request implies --json
        elif flag == "--json-request-file":
            if not argv:
                emit_error(json_mode, "--json-request-file requires a path")
            json_request_file = argv.pop(0)
            json_request = True
            json_mode = True
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
        elif flag == "--read-file":
            if not argv:
                emit_error(json_mode, "--read-file requires a remote path")
            read_file_path = argv.pop(0)
        elif flag == "--write-file":
            if not argv:
                emit_error(json_mode, "--write-file requires a remote dest path")
            write_file_dest = argv.pop(0)
        elif flag == "--copy-file":
            if len(argv) < 2:
                emit_error(json_mode, "--copy-file requires LOCAL and DEST paths")
            copy_local = argv.pop(0)
            copy_dest = argv.pop(0)
        elif flag == "--search":
            if len(argv) < 2:
                emit_error(json_mode, "--search requires REMOTE_ROOT and QUERY")
            search_root = argv.pop(0)
            search_query = argv.pop(0)
        elif flag == "--list-dir":
            if not argv:
                emit_error(json_mode, "--list-dir requires a remote path")
            list_dir_path = argv.pop(0)
        elif flag == "--mode":
            if not argv:
                emit_error(json_mode, "--mode requires one of: create, overwrite, append")
            op_mode = argv.pop(0)
            if op_mode not in ("create", "overwrite", "append"):
                emit_error(json_mode, "--mode must be one of: create, overwrite, append")
        elif flag == "--mkdirs":
            mkdirs = True
        elif flag == "--glob":
            if not argv:
                emit_error(json_mode, "--glob requires a pattern")
            glob = argv.pop(0)
        elif flag == "--ignore-case":
            ignore_case = True
        elif flag == "--fixed-strings":
            fixed_strings = True
        elif flag == "--":
            break
        else:
            emit_error(json_mode, f"unknown flag: {flag}")

    # --- Filesystem operation modes (mutually exclusive with each other, with
    # --json-request, and with positional command/args) ---
    fs_modes = [
        ("--read-file", read_file_path is not None),
        ("--write-file", write_file_dest is not None),
        ("--copy-file", copy_local is not None),
        ("--search", search_root is not None),
        ("--list-dir", list_dir_path is not None),
    ]
    active = [name for name, on in fs_modes if on]
    if len(active) > 1:
        emit_error(json_mode, f"these flags are mutually exclusive: {', '.join(active)}")

    if active:
        mode_name = active[0]
        if argv:
            emit_error(json_mode, f"{mode_name} cannot be combined with positional command/args")
        if json_request:
            emit_error(json_mode, f"{mode_name} cannot be combined with --json-request")
        if mode_name != "--copy-file" and files:
            emit_error(json_mode, f"{mode_name} cannot be combined with --file")
        if not TOKEN:
            emit_error(json_mode, "EXEC_API_TOKEN not set")

        if mode_name == "--read-file":
            payload = json.dumps({"path": read_file_path}).encode()
            req_fn = lambda: do_read_file_request(  # noqa: E731
                f"{BASE_URL}/read-file", payload, read_file_path
            )
        elif mode_name == "--write-file":
            content = b"" if sys.stdin.isatty() else sys.stdin.buffer.read()
            payload = json.dumps({
                "path": write_file_dest,
                "content_base64": base64.b64encode(content).decode(),
                "mode": op_mode,
                "mkdirs": mkdirs,
            }).encode()
            label = ["write-file", write_file_dest]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/write-file", payload, label
            )
        elif mode_name == "--copy-file":
            upload = load_input_file(json_mode, copy_local)
            payload = json.dumps({
                "file": "@file:0",
                "dest": copy_dest,
                "mode": op_mode,
                "mkdirs": mkdirs,
                "files": [upload],
            }).encode()
            label = ["copy-file", copy_local, copy_dest]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/copy-uploaded-file", payload, label
            )
        elif mode_name == "--search":
            search_body = {
                "root": search_root,
                "query": search_query,
                "ignore_case": ignore_case,
                "fixed_strings": fixed_strings,
            }
            if glob:
                search_body["glob"] = glob
            payload = json.dumps(search_body).encode()
            label = ["search", search_root, search_query]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/search-files", payload, label
            )
        else:  # --list-dir
            payload = json.dumps({"path": list_dir_path}).encode()
            label = ["list-dir", list_dir_path]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/list-dir", payload, label
            )

        envelope, result = run_with_retries(req_fn, retries, retry_on, json_mode)

        if json_mode:
            print(json.dumps(envelope))
            sys.exit(0)

        if result is None:
            print(f"error: {envelope.get('detail', 'unknown error')}", file=sys.stderr)
            sys.exit(1)

        if mode_name == "--read-file":
            try:
                raw_bytes = base64.b64decode(result["content_base64"], validate=True)
            except (KeyError, ValueError) as exc:
                print(f"error: invalid response: {exc}", file=sys.stderr)
                sys.exit(1)
            sys.stdout.buffer.write(raw_bytes)
        elif mode_name in ("--write-file", "--copy-file"):
            verb = "created" if result.get("created") else "wrote"
            print(
                f"{verb} {result.get('path')} ({result.get('size')} bytes, "
                f"sha256 {str(result.get('sha256'))[:12]})"
            )
        elif mode_name == "--search":
            for m in result.get("matches", []):
                if m.get("path") is not None:
                    print(f"{m['path']}:{m.get('line')}:{m.get('text')}")
                else:
                    print(m.get("text", ""))
            if result.get("truncated"):
                print("(results truncated)", file=sys.stderr)
        else:  # --list-dir
            for e in result.get("entries", []):
                print(f"{e.get('type', '?')[0]}\t{e.get('size'):>10}\t{e.get('name')}")
            if result.get("truncated"):
                print("(listing truncated)", file=sys.stderr)
        sys.exit(0)

    if json_request:
        # --json-request / --json-request-file mode
        if argv:
            emit_error(json_mode, "--json-request cannot be combined with positional command/args")
        if files:
            emit_error(json_mode, "--json-request cannot be combined with --file")
        if stdin_mode != "auto":
            emit_error(json_mode, "--json-request cannot be combined with --stdin/--no-stdin")
        raw = None
        if json_request_file is not None:
            if not os.path.isfile(json_request_file):
                emit_error(json_mode, f"file not found: {json_request_file}")
            try:
                with open(json_request_file) as fh:
                    raw = fh.read()
            except OSError as exc:
                emit_error(json_mode, f"failed to read request file: {exc}")
        command, args, body = parse_json_request(json_mode, raw)
    else:
        if len(argv) < 1:
            emit_error(
                json_mode,
                "usage: run.py [--json] [--json-request] [--json-request-file PATH] "
                "[--retry N] [--retry-on transport|any] [--stdin auto|always|never|--no-stdin] "
                "[--file PATH ...] [--read-file REMOTE_PATH] [--write-file DEST] "
                "[--copy-file LOCAL DEST] [--search ROOT QUERY] [--list-dir PATH] "
                "[--mode create|overwrite|append] [--mkdirs] [--glob PAT] "
                "[--ignore-case] [--fixed-strings] <command> [args...]",
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

    url = f"{BASE_URL}/run"
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
