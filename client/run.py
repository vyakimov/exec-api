#!/usr/bin/env python3
"""CLI client for exec-api. No dependencies beyond stdlib."""

import argparse
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


def _http_post(url, payload, label, method="POST"):
    """Send a JSON request. Returns (error_envelope_or_None, result_or_None, elapsed_ms)."""
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
        method=method,
    )

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=35) as resp:
            result = json.loads(resp.read())
        return None, result, round((time.monotonic() - t0) * 1000)
    except urllib.error.HTTPError as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        body = e.read().decode(errors="replace")
        return build_envelope(
            ok=False,
            error_type="request",
            command=label,
            detail=f"HTTP {e.code}: {body}",
            timing_total_ms=elapsed,
        ), None, elapsed
    except (urllib.error.URLError, OSError) as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        reason = getattr(e, "reason", str(e))
        return build_envelope(
            ok=False,
            error_type="transport",
            command=label,
            detail=f"cannot reach exec API at {HOST}: {reason}",
            timing_total_ms=elapsed,
        ), None, elapsed


def do_request(url, payload, command, args):
    """Execute one /run request. Returns (envelope_dict, raw_result_or_None)."""
    label = [command] + args
    error, result, elapsed = _http_post(url, payload, label)
    if error is not None:
        return error, None

    cmd_ok = result.get("code", 0) == 0
    return build_envelope(
        ok=cmd_ok,
        error_type=None if cmd_ok else "command",
        command=label,
        exit_code=result.get("code", 0),
        stdout=result.get("stdout", ""),
        stderr=result.get("stderr", ""),
        timing_total_ms=elapsed,
        timing_exec_ms=result.get("exec_ms"),
    ), result


def do_read_file_request(url, payload, path):
    """Execute one /read-file request. Returns (envelope_dict, raw_result_or_None)."""
    label = ["read-file", path]
    error, result, elapsed = _http_post(url, payload, label)
    if error is not None:
        return error, None

    envelope = build_envelope(
        ok=True,
        command=label,
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


def do_op_request(url, payload, label, method="POST"):
    """Execute one request to a filesystem-operation endpoint.

    Returns (envelope_dict, raw_result_or_None). The raw server response is
    attached to the envelope under "result" on success.
    """
    error, result, elapsed = _http_post(url, payload, label, method=method)
    if error is not None:
        return error, None

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


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose errors go through emit_error.

    In --json mode a usage error must still print a JSON envelope and exit 0;
    argparse's default (usage text on stderr, exit 2) would break the "one
    parser, always an envelope" contract.
    """

    json_mode = False

    def error(self, message):
        emit_error(self.json_mode, message)


def build_parser():
    parser = _Parser(
        prog="exec-api",
        description="CLI client for exec-api: run allowlisted remote commands "
                    "and policy-checked filesystem operations.",
    )
    parser.add_argument("--json", action="store_true",
                        help="emit a JSON envelope (always exits 0)")
    parser.add_argument("--json-request", action="store_true",
                        help="read a structured JSON request from stdin (implies --json)")
    parser.add_argument("--json-request-file", metavar="PATH",
                        help="read a structured JSON request from a file (implies --json)")
    parser.add_argument("--retry", type=int, default=0, metavar="N",
                        help=f"retry attempts, 0-{MAX_RETRIES}")
    parser.add_argument("--retry-on", choices=RETRY_ON_CHOICES, default="transport",
                        help="which errors to retry")
    parser.add_argument("--stdin", choices=STDIN_MODE_CHOICES, default="auto",
                        dest="stdin_mode", help="when to forward local stdin")
    parser.add_argument("--no-stdin", action="store_const", const="never",
                        dest="stdin_mode", help="never forward local stdin")
    parser.add_argument("--file", action="append", default=[], dest="file_paths",
                        metavar="PATH", help="upload a local file (repeatable)")
    parser.add_argument("--read-file", metavar="REMOTE_PATH")
    parser.add_argument("--write-file", metavar="DEST")
    parser.add_argument("--copy-file", nargs=2, metavar=("LOCAL", "DEST"))
    parser.add_argument("--search", nargs=2, metavar=("ROOT", "QUERY"))
    parser.add_argument("--list-dir", metavar="PATH")
    parser.add_argument("--delete-file", metavar="PATH")
    parser.add_argument("--move-file", nargs=2, metavar=("SRC", "DEST"))
    parser.add_argument("--capabilities", action="store_true",
                        help="show this token's policy view")
    parser.add_argument("--mode", choices=("create", "overwrite", "append"),
                        default="create", dest="op_mode")
    parser.add_argument("--mkdirs", action="store_true")
    parser.add_argument("--glob", metavar="PAT")
    parser.add_argument("--ignore-case", action="store_true")
    parser.add_argument("--fixed-strings", action="store_true")
    return parser


_JSON_FLAGS = ("--json", "--json-request", "--json-request-file")


def split_wrapper_args(parser, argv):
    """Split argv into (wrapper flags, remote command+args).

    Wrapper flags end at the first token that is not a recognized --flag (or
    at a literal `--`); everything after passes to the remote command
    untouched, even if it looks like a flag. This is the contract that lets
    `exec-api mycmd --verbose` forward --verbose instead of eating it.
    """
    value_counts = {}
    for action in parser._actions:
        for opt in action.option_strings:
            n = action.nargs
            value_counts[opt] = 0 if n == 0 else (n if isinstance(n, int) else 1)

    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return argv[:i], argv[i + 1:]
        if not tok.startswith("--"):
            return argv[:i], argv[i:]
        base, eq, _ = tok.partition("=")
        if base not in value_counts:
            json_hint = any(t.partition("=")[0] in _JSON_FLAGS for t in argv[:i])
            emit_error(json_hint, f"unknown flag: {tok}")
        i += 1 if eq else 1 + value_counts[base]
    return argv, []


def main():
    parser = build_parser()
    wrapper, argv = split_wrapper_args(parser, sys.argv[1:])
    parser.json_mode = any(t.partition("=")[0] in _JSON_FLAGS for t in wrapper)
    ns = parser.parse_args(wrapper)

    json_request = ns.json_request or ns.json_request_file is not None
    json_mode = ns.json or json_request
    json_request_file = ns.json_request_file
    if ns.retry < 0 or ns.retry > MAX_RETRIES:
        emit_error(json_mode, f"--retry must be 0-{MAX_RETRIES}")
    retries = ns.retry
    retry_on = ns.retry_on
    stdin_mode = ns.stdin_mode
    files = [load_input_file(json_mode, path) for path in ns.file_paths]
    read_file_path = ns.read_file
    write_file_dest = ns.write_file
    copy_local, copy_dest = ns.copy_file or (None, None)
    search_root, search_query = ns.search or (None, None)
    list_dir_path = ns.list_dir
    delete_file_path = ns.delete_file
    move_src, move_dest = ns.move_file or (None, None)
    show_capabilities = ns.capabilities
    op_mode = ns.op_mode
    mkdirs = ns.mkdirs
    glob = ns.glob
    ignore_case = ns.ignore_case
    fixed_strings = ns.fixed_strings

    # --- Filesystem operation modes (mutually exclusive with each other, with
    # --json-request, and with positional command/args) ---
    fs_modes = [
        ("--read-file", read_file_path is not None),
        ("--write-file", write_file_dest is not None),
        ("--copy-file", copy_local is not None),
        ("--search", search_root is not None),
        ("--list-dir", list_dir_path is not None),
        ("--delete-file", delete_file_path is not None),
        ("--move-file", move_src is not None),
        ("--capabilities", show_capabilities),
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
        elif mode_name == "--list-dir":
            payload = json.dumps({"path": list_dir_path}).encode()
            label = ["list-dir", list_dir_path]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/list-dir", payload, label
            )
        elif mode_name == "--delete-file":
            payload = json.dumps({"path": delete_file_path}).encode()
            label = ["delete-file", delete_file_path]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/delete-file", payload, label
            )
        elif mode_name == "--move-file":
            payload = json.dumps({
                "src": move_src,
                "dest": move_dest,
                "mode": op_mode,
                "mkdirs": mkdirs,
            }).encode()
            label = ["move-file", move_src, move_dest]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/move-file", payload, label
            )
        else:  # --capabilities
            label = ["capabilities"]
            req_fn = lambda: do_op_request(  # noqa: E731
                f"{BASE_URL}/capabilities", None, label, method="GET"
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
        elif mode_name == "--list-dir":
            for e in result.get("entries", []):
                print(f"{e.get('type', '?')[0]}\t{e.get('size'):>10}\t{e.get('name')}")
            if result.get("truncated"):
                print("(listing truncated)", file=sys.stderr)
        elif mode_name == "--delete-file":
            print(f"deleted {result.get('path')}")
        elif mode_name == "--move-file":
            print(f"moved {result.get('src')} -> {result.get('path')}")
        else:  # --capabilities
            print(json.dumps(result, indent=2))
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
                "[--delete-file PATH] [--move-file SRC DEST] [--capabilities] "
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

    envelope, result = run_with_retries(
        lambda: do_request(url, payload, command, args), retries, retry_on, json_mode
    )

    if json_mode:
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
