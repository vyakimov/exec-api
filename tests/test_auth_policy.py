"""Auth + per-principal policy tests for exec-api.

Covers: legacy single-token mode, token->principal resolution, partner denial of
filesystem ops, per-policy command allowlisting, per-command env injection, and the
startup-fatal misconfiguration paths.
"""

import base64

import pytest
from fastapi.testclient import TestClient


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _base_config(tmp_path, stub):
    """Top-level (default) config: real read/write dirs and a command registry."""
    read_dir = tmp_path / "read"
    write_dir = tmp_path / "write"
    read_dir.mkdir()
    write_dir.mkdir()
    (read_dir / "hello.txt").write_text("hello world\n")
    return {
        "filesystem": {
            "read_prefixes": [str(read_dir)],
            "write_prefixes": [str(write_dir)],
        },
        "operations": {
            "read_file": True,
            "write_file": True,
            "copy_uploaded_file": True,
            "search_files": True,
            "list_dir": True,
        },
        "commands": {
            "inventory": {"allowed": True, "executable": stub},
            "huckctl": {"allowed": True, "executable": stub},
            "ynab": {"allowed": True, "executable": stub},
            "ping": {"allowed": True, "executable": stub},
        },
        "_read_dir": str(read_dir),
        "_write_dir": str(write_dir),
    }


def _strip_private(config):
    return {k: v for k, v in config.items() if not k.startswith("_")}


# --- Legacy single-token mode -------------------------------------------------

def test_legacy_mode_full_access(load_server, tmp_path, stub_cmd):
    config = _base_config(tmp_path, stub_cmd)
    read_dir, write_dir = config["_read_dir"], config["_write_dir"]
    server = load_server(_strip_private(config), {"EXEC_API_TOKEN": "owner-token"})
    client = TestClient(server.app)

    # read a file under the read prefix
    r = client.post("/read-file", json={"path": f"{read_dir}/hello.txt"}, headers=_bearer("owner-token"))
    assert r.status_code == 200
    assert base64.b64decode(r.json()["content_base64"]) == b"hello world\n"

    # write a file under the write prefix
    payload = {"path": f"{write_dir}/out.txt", "content_base64": base64.b64encode(b"hi").decode()}
    r = client.post("/write-file", json=payload, headers=_bearer("owner-token"))
    assert r.status_code == 200

    # run an allowlisted command
    r = client.post("/run", json={"command": "ping"}, headers=_bearer("owner-token"))
    assert r.status_code == 200

    # wrong token is rejected
    r = client.post("/run", json={"command": "ping"}, headers=_bearer("nope"))
    assert r.status_code == 401


def test_legacy_mode_missing_token_is_fatal(load_server, tmp_path, stub_cmd):
    config = _strip_private(_base_config(tmp_path, stub_cmd))
    with pytest.raises(SystemExit):
        load_server(config, {})  # EXEC_API_TOKEN unset


# --- Multi-principal config ---------------------------------------------------

def _multiuser_config(tmp_path, stub):
    config = _base_config(tmp_path, stub)
    config["auth"] = {
        "tokens": {
            "victor": {"env": "EXEC_API_TOKEN", "policy": "owner"},
            "emma": {"env": "EXEC_API_TOKEN_EMMA", "policy": "partner"},
        }
    }
    config["policies"] = {
        "owner": {
            "filesystem": "inherit_default",
            "operations": "inherit_default",
            "commands": "inherit_default",
        },
        "partner": {
            "filesystem": {"read_prefixes": [], "write_prefixes": []},
            "operations": {},
            "commands": {
                "inventory": {},
                "huckctl": {},
                "ynab": {"env": {"YNAB_PROFILE": "emma"}},
            },
        },
    }
    return config


@pytest.fixture
def multiuser(load_server, tmp_path, stub_cmd):
    config = _multiuser_config(tmp_path, stub_cmd)
    env = {"EXEC_API_TOKEN": "victor-token", "EXEC_API_TOKEN_EMMA": "emma-token"}
    server = load_server(_strip_private(config), env)
    return server, config


def test_token_resolves_to_principal(multiuser):
    server, config = multiuser
    client = TestClient(server.app)

    # victor (owner) can run ping; emma (partner) cannot (not in her policy)
    assert client.post("/run", json={"command": "ping"}, headers=_bearer("victor-token")).status_code == 200
    assert client.post("/run", json={"command": "ping"}, headers=_bearer("emma-token")).status_code == 403

    # unknown and empty tokens are rejected
    assert client.post("/run", json={"command": "ping"}, headers=_bearer("bogus")).status_code == 401
    assert client.post("/run", json={"command": "ping"}, headers=_bearer("")).status_code == 401


@pytest.mark.parametrize(
    "path, body",
    [
        ("/read-file", {"path": "/etc/hosts"}),
        ("/write-file", {"path": "/tmp/x", "content_base64": ""}),
        ("/list-dir", {"path": "/tmp"}),
        ("/search-files", {"root": "/tmp", "query": "x"}),
        ("/copy-uploaded-file", {"file": "@file:0", "dest": "/tmp/x",
                                 "files": [{"name": "a", "content_base64": base64.b64encode(b"a").decode()}]}),
    ],
)
def test_partner_filesystem_ops_disabled(multiuser, path, body):
    server, _ = multiuser
    client = TestClient(server.app)
    r = client.post(path, json=body, headers=_bearer("emma-token"))
    # operations are off for partner -> 404, never reaching a path/prefix check
    assert r.status_code == 404


def test_partner_command_allow_and_deny(multiuser):
    server, _ = multiuser
    client = TestClient(server.app)
    # allowed for partner
    assert client.post("/run", json={"command": "inventory"}, headers=_bearer("emma-token")).status_code == 200
    assert client.post("/run", json={"command": "huckctl"}, headers=_bearer("emma-token")).status_code == 200
    # ping is in owner's set but not partner's
    assert client.post("/run", json={"command": "ping"}, headers=_bearer("emma-token")).status_code == 403


def test_env_injection(multiuser):
    server, _ = multiuser
    client = TestClient(server.app)

    # emma's ynab invocation has YNAB_PROFILE injected
    r = client.post("/run", json={"command": "ynab"}, headers=_bearer("emma-token"))
    assert r.status_code == 200
    assert "PROFILE=emma" in r.json()["stdout"]

    # owner inherits the registry but no env override -> profile unset
    r = client.post("/run", json={"command": "ynab"}, headers=_bearer("victor-token"))
    assert r.status_code == 200
    assert "PROFILE=unset" in r.json()["stdout"]


# --- Startup-fatal misconfigurations ------------------------------------------

def test_fatal_unset_token_env(load_server, tmp_path, stub_cmd):
    config = _strip_private(_multiuser_config(tmp_path, stub_cmd))
    with pytest.raises(SystemExit):
        # EXEC_API_TOKEN_EMMA missing
        load_server(config, {"EXEC_API_TOKEN": "victor-token"})


def test_fatal_duplicate_token_values(load_server, tmp_path, stub_cmd):
    config = _strip_private(_multiuser_config(tmp_path, stub_cmd))
    with pytest.raises(SystemExit):
        load_server(config, {"EXEC_API_TOKEN": "same", "EXEC_API_TOKEN_EMMA": "same"})


def test_fatal_unknown_command_in_policy(load_server, tmp_path, stub_cmd):
    config = _multiuser_config(tmp_path, stub_cmd)
    config["policies"]["partner"]["commands"]["does_not_exist"] = {}
    with pytest.raises(SystemExit):
        load_server(_strip_private(config),
                    {"EXEC_API_TOKEN": "victor-token", "EXEC_API_TOKEN_EMMA": "emma-token"})


def test_fatal_op_enabled_without_prefix(load_server, tmp_path, stub_cmd):
    config = _multiuser_config(tmp_path, stub_cmd)
    # enable read_file for partner but leave read_prefixes empty -> fail closed
    config["policies"]["partner"]["operations"] = {"read_file": True}
    with pytest.raises(SystemExit):
        load_server(_strip_private(config),
                    {"EXEC_API_TOKEN": "victor-token", "EXEC_API_TOKEN_EMMA": "emma-token"})
