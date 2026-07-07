"""/run behaviour: stdin, uploads/placeholders, timeouts, cwd, env hygiene.

Plus the request-wide guards (body cap, auth header shapes) and the discovery
endpoints (/capabilities, /healthz).
"""

import base64

import pytest
from fastapi.testclient import TestClient

H = {"Authorization": "Bearer tok"}

ALL_OPS = (
    "read_file", "write_file", "copy_uploaded_file", "search_files", "list_dir",
    "delete_file", "move_file",
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.fixture
def echo_stub(tmp_path):
    """Prints argv (one per line), then stdin, then selected env vars."""
    path = tmp_path / "echo-stub"
    path.write_text(
        '#!/bin/sh\n'
        'for a in "$@"; do printf "ARG:%s\\n" "$a"; done\n'
        'if [ ! -t 0 ]; then while IFS= read -r l; do printf "IN:%s\\n" "$l"; done; fi\n'
        'printf "TOKEN:[%s]\\n" "$EXEC_API_TOKEN"\n'
        'printf "CWD:%s\\n" "$(pwd)"\n'
    )
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def slow_stub(tmp_path):
    path = tmp_path / "slow-stub"
    path.write_text("#!/bin/sh\nsleep 5\n")
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def env(load_server, tmp_path, echo_stub, slow_stub):
    read_dir = tmp_path / "read"
    write_dir = tmp_path / "write"
    cwd_dir = tmp_path / "workdir"
    for d in (read_dir, write_dir, cwd_dir):
        d.mkdir()
    config = {
        "filesystem": {
            "read_prefixes": [str(read_dir)],
            "write_prefixes": [str(write_dir)],
        },
        "command_timeout": 1,
        "operations": dict.fromkeys(ALL_OPS, True),
        "commands": {
            "echo-stub": {"allowed": True, "executable": echo_stub},
            "pinned": {"allowed": True, "executable": echo_stub, "cwd": str(cwd_dir)},
            "slow": {"allowed": True, "executable": slow_stub},
        },
    }
    server = load_server(config, {"EXEC_API_TOKEN": "tok"})
    return server, TestClient(server.app), cwd_dir


def test_missing_and_malformed_auth(env):
    _, client, _ = env
    assert client.post("/run", json={"command": "echo-stub"}).status_code == 401
    assert client.post(
        "/run", json={"command": "echo-stub"}, headers={"Authorization": "tok"}
    ).status_code == 401
    assert client.post(
        "/run", json={"command": "echo-stub"}, headers={"Authorization": "Basic tok"}
    ).status_code == 401


def test_unknown_command_403(env):
    _, client, _ = env
    r = client.post("/run", json={"command": "nope"}, headers=H)
    assert r.status_code == 403


def test_stdin_roundtrip_and_limits(env):
    server, client, _ = env
    r = client.post(
        "/run", json={"command": "echo-stub", "stdin_text": "hello\n"}, headers=H
    )
    assert r.status_code == 200
    assert "IN:hello" in r.json()["stdout"]

    r = client.post(
        "/run",
        json={"command": "echo-stub", "stdin_text": "x", "stdin_encoding": "latin-1"},
        headers=H,
    )
    assert r.status_code == 400

    too_big = "x" * (server.STDIN_MAX_BYTES + 1)
    r = client.post(
        "/run", json={"command": "echo-stub", "stdin_text": too_big}, headers=H
    )
    assert r.status_code == 400


def test_file_placeholders(env):
    _, client, _ = env
    files = [
        {"name": "a.txt", "content_base64": _b64(b"A")},
        {"name": "b.txt", "content_base64": _b64(b"B")},
    ]
    r = client.post(
        "/run",
        json={"command": "echo-stub", "files": files,
              "args": ["@file:0", "@file:b.txt", "@filesdir"]},
        headers=H,
    )
    assert r.status_code == 200
    out = r.json()["stdout"]
    args = [line[4:] for line in out.splitlines() if line.startswith("ARG:")]
    assert args[0].endswith("/a.txt")
    assert args[1].endswith("/b.txt")
    assert args[2] == args[0].rsplit("/", 1)[0]  # @filesdir is the staging dir
    assert len(args) == 3  # both files referenced -> nothing auto-appended


def test_unreferenced_files_appended(env):
    _, client, _ = env
    r = client.post(
        "/run",
        json={"command": "echo-stub", "args": ["first"],
              "files": [{"name": "a.txt", "content_base64": _b64(b"A")}]},
        headers=H,
    )
    args = [line for line in r.json()["stdout"].splitlines() if line.startswith("ARG:")]
    assert args[0] == "ARG:first"
    assert args[1].endswith("/a.txt")


def test_unknown_placeholder_400(env):
    _, client, _ = env
    r = client.post(
        "/run",
        json={"command": "echo-stub", "args": ["@file:missing"],
              "files": [{"name": "a.txt", "content_base64": _b64(b"A")}]},
        headers=H,
    )
    assert r.status_code == 400
    r = client.post(
        "/run", json={"command": "echo-stub", "args": ["@filesdir"]}, headers=H
    )
    assert r.status_code == 400


def test_upload_validation(env, monkeypatch):
    server, client, _ = env
    dup = [
        {"name": "a.txt", "content_base64": _b64(b"1")},
        {"name": "a.txt", "content_base64": _b64(b"2")},
    ]
    r = client.post("/run", json={"command": "echo-stub", "files": dup}, headers=H)
    assert r.status_code == 400

    r = client.post(
        "/run",
        json={"command": "echo-stub",
              "files": [{"name": "a.txt", "content_base64": "!!bad!!"}]},
        headers=H,
    )
    assert r.status_code == 400

    # path separators in names are rejected at the model layer
    r = client.post(
        "/run",
        json={"command": "echo-stub",
              "files": [{"name": "../evil", "content_base64": _b64(b"x")}]},
        headers=H,
    )
    assert r.status_code == 422

    # size caps (shrunk so the test stays cheap)
    monkeypatch.setattr(server, "FILE_MAX_BYTES", 10)
    r = client.post(
        "/run",
        json={"command": "echo-stub",
              "files": [{"name": "big", "content_base64": _b64(b"x" * 11)}]},
        headers=H,
    )
    assert r.status_code == 400

    monkeypatch.setattr(server, "FILE_MAX_BYTES", 100)
    monkeypatch.setattr(server, "FILES_TOTAL_MAX_BYTES", 150)
    files = [
        {"name": "f1", "content_base64": _b64(b"x" * 100)},
        {"name": "f2", "content_base64": _b64(b"x" * 100)},
    ]
    r = client.post("/run", json={"command": "echo-stub", "files": files}, headers=H)
    assert r.status_code == 400


def test_token_env_not_leaked_to_child(env):
    _, client, _ = env
    r = client.post("/run", json={"command": "echo-stub"}, headers=H)
    assert r.status_code == 200
    assert "TOKEN:[]" in r.json()["stdout"]


def test_timeout_kills_command(env):
    _, client, _ = env
    r = client.post("/run", json={"command": "slow"}, headers=H)
    assert r.status_code == 408


def test_per_command_cwd(env):
    _, client, cwd_dir = env
    r = client.post("/run", json={"command": "pinned"}, headers=H)
    assert r.status_code == 200
    assert f"CWD:{cwd_dir}" in r.json()["stdout"]


def test_body_size_cap(env):
    server, client, _ = env
    blob = b'{"command": "' + b"A" * server.app.state.exec.max_body_bytes + b'"}'
    r = client.post(
        "/run", content=blob,
        headers={**H, "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_healthz_unauthenticated(env):
    _, client, _ = env
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_capabilities_reports_policy(env):
    _, client, cwd_dir = env
    assert client.get("/capabilities").status_code == 401  # auth required

    r = client.get("/capabilities", headers=H)
    assert r.status_code == 200
    caps = r.json()
    assert caps["principal"] == "owner"
    assert caps["operations"]["read_file"] is True
    assert set(caps["commands"]) == {"echo-stub", "pinned", "slow"}
    assert caps["commands"]["pinned"]["cwd"] == str(cwd_dir)
    assert caps["commands"]["slow"]["timeout"] == 1
    assert caps["limits"]["command_timeout"] == 1
    assert len(caps["read_prefixes"]) == 1


def test_denylisted_executable_alias_not_registered(load_server, tmp_path, echo_stub):
    config = {
        "filesystem": {"read_prefixes": [str(tmp_path)], "write_prefixes": [str(tmp_path)]},
        "operations": {},
        "commands": {
            "ok": {"allowed": True, "executable": echo_stub},
            "sneaky": {"allowed": True, "executable": "/bin/sh"},
            "bash": {"allowed": True},
        },
    }
    server = load_server(config, {"EXEC_API_TOKEN": "tok"})
    registry = server.app.state.exec.command_registry
    assert "ok" in registry
    assert "sneaky" not in registry
    assert "bash" not in registry
