"""Unit tests for the stdlib client's pure logic (no network)."""

import importlib.util
import json
import os
import sys

import pytest

CLIENT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "client", "run.py")


def _load_client(monkeypatch, host=None):
    if host is not None:
        monkeypatch.setenv("EXEC_API_HOST", host)
    else:
        monkeypatch.delenv("EXEC_API_HOST", raising=False)
    spec = importlib.util.spec_from_file_location("execapi_client", CLIENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def client_mod(monkeypatch):
    return _load_client(monkeypatch)


# --- base URL derivation --------------------------------------------------

def test_base_url_default(monkeypatch):
    mod = _load_client(monkeypatch)
    assert mod.BASE_URL == "http://127.0.0.1:8019"


def test_base_url_bare_hostport(monkeypatch):
    mod = _load_client(monkeypatch, host="box:9000")
    assert mod.BASE_URL == "http://box:9000"


def test_base_url_with_scheme(monkeypatch):
    mod = _load_client(monkeypatch, host="https://exec.example.com/")
    assert mod.BASE_URL == "https://exec.example.com"


# --- retry decisions --------------------------------------------------------

@pytest.mark.parametrize(
    "error_type,retry_on,expected",
    [
        ("transport", "transport", True),
        ("transport", "any", True),
        ("command", "transport", False),
        ("command", "any", True),
        ("request", "transport", False),
        ("request", "any", False),
        ("usage", "any", False),
        (None, "any", False),
    ],
)
def test_should_retry(client_mod, error_type, retry_on, expected):
    envelope = {"error_type": error_type}
    assert client_mod.should_retry(envelope, retry_on) is expected


def test_run_with_retries_counts_attempts(client_mod, monkeypatch):
    monkeypatch.setattr(client_mod, "backoff_sleep", lambda attempt: None)
    calls = []

    def failing():
        calls.append(1)
        return {"ok": False, "error_type": "transport"}, None

    envelope, result = client_mod.run_with_retries(failing, retries=2,
                                                   retry_on="transport", json_mode=True)
    assert len(calls) == 3
    assert envelope["attempts"] == 3

    calls.clear()

    def failing_request():
        calls.append(1)
        return {"ok": False, "error_type": "request"}, None

    envelope, _ = client_mod.run_with_retries(failing_request, retries=2,
                                              retry_on="transport", json_mode=True)
    assert len(calls) == 1  # request errors are not retriable
    assert envelope["attempts"] == 1


# --- envelope shape ---------------------------------------------------------

def test_build_envelope_shape(client_mod):
    env = client_mod.build_envelope(ok=True, command=["echo"], exit_code=0,
                                    stdout="x", stderr="", timing_total_ms=5)
    assert env["ok"] is True
    assert env["transport"] == "exec-api"
    assert "detail" not in env

    env = client_mod.build_envelope(ok=False, error_type="usage", detail="bad flag")
    assert env["detail"] == "bad flag"
    assert env["error_type"] == "usage"


# --- --json-request parsing -------------------------------------------------

def _parse_ok(client_mod, raw):
    return client_mod.parse_json_request(True, raw)


def test_parse_json_request_valid(client_mod):
    command, args, body = _parse_ok(client_mod, json.dumps({
        "command": "echo",
        "argv": ["a", "b"],
        "stdin": "input",
        "files": [{"name": "f.txt", "content_base64": "QQ=="}],
    }))
    assert command == "echo"
    assert args == ["a", "b"]
    assert body["stdin_text"] == "input"
    assert body["stdin_encoding"] == "utf-8"
    assert body["files"][0]["name"] == "f.txt"


def test_parse_json_request_minimal(client_mod):
    command, args, body = _parse_ok(client_mod, '{"command": "ls"}')
    assert command == "ls" and args == []
    assert "stdin_text" not in body and "files" not in body


@pytest.mark.parametrize(
    "raw",
    [
        "",                                        # empty
        "not json",                                # invalid JSON
        '["not", "an", "object"]',                 # not a dict
        '{"argv": ["x"]}',                         # missing command
        '{"command": 42}',                         # command not a string
        '{"command": "x", "argv": "not-a-list"}',  # argv wrong type
        '{"command": "x", "argv": [1]}',           # argv non-string element
        '{"command": "x", "stdin": 42}',           # stdin wrong type
        '{"command": "x", "files": "nope"}',       # files wrong type
        '{"command": "x", "files": [{}]}',         # file missing keys
    ],
)
def test_parse_json_request_errors(client_mod, capsys, raw):
    # In JSON mode a usage error prints an envelope and exits 0.
    with pytest.raises(SystemExit) as exc_info:
        client_mod.parse_json_request(True, raw)
    assert exc_info.value.code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False
    assert envelope["error_type"] == "usage"


def test_emit_error_plain_mode_exits_1(client_mod, capsys):
    with pytest.raises(SystemExit) as exc_info:
        client_mod.emit_error(False, "boom")
    assert exc_info.value.code == 1
    assert "boom" in capsys.readouterr().err


def test_load_input_file_roundtrip(client_mod, tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00\x01binary")
    upload = client_mod.load_input_file(True, str(f))
    assert upload["name"] == "data.bin"
    import base64
    assert base64.b64decode(upload["content_base64"]) == b"\x00\x01binary"


def test_load_input_file_missing(client_mod, capsys):
    with pytest.raises(SystemExit):
        client_mod.load_input_file(True, "/nonexistent/file")
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["error_type"] == "usage"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
