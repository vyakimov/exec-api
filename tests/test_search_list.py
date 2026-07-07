"""Search (both engines) and list-dir behaviour.

The rg and Python engines must return the same results for the same tree; the
`engine` fixture parameter runs every search test against both (rg tests skip
when ripgrep isn't installed).
"""

import os
import shutil

import pytest
from fastapi.testclient import TestClient

H = {"Authorization": "Bearer tok"}

ALL_OPS = (
    "read_file", "write_file", "copy_uploaded_file", "search_files", "list_dir",
    "delete_file", "move_file",
)

HAS_RG = shutil.which("rg") is not None


@pytest.fixture
def env(load_server, tmp_path, stub_cmd):
    read_dir = tmp_path / "read"
    write_dir = tmp_path / "write"
    read_dir.mkdir()
    write_dir.mkdir()
    (read_dir / "one.txt").write_text("a needle here\nnothing\nNEEDLE again\n")
    (read_dir / "two.py").write_text("needle = 1\n")
    (read_dir / ".hidden").write_text("hidden needle\n")
    (read_dir / ".gitignore").write_text("ignored.txt\n")
    (read_dir / "ignored.txt").write_text("ignored needle\n")
    sub = read_dir / "sub"
    sub.mkdir()
    (sub / "three.txt").write_text("deep needle\n")
    config = {
        "filesystem": {
            "read_prefixes": [str(read_dir)],
            "write_prefixes": [str(write_dir)],
        },
        "operations": dict.fromkeys(ALL_OPS, True),
        "commands": {"ping": {"allowed": True, "executable": stub_cmd}},
    }
    server = load_server(config, {"EXEC_API_TOKEN": "tok"})
    return server, TestClient(server.app), read_dir


@pytest.fixture(params=["rg", "python"])
def engine(request, env):
    server, client, read_dir = env
    if request.param == "rg":
        if not HAS_RG:
            pytest.skip("ripgrep not installed")
    else:
        server.SEARCH_BINARY = None
    return client, read_dir, request.param


def _search(client, read_dir, **kwargs):
    body = {"root": str(read_dir), "query": "needle", **kwargs}
    return client.post("/search-files", json=body, headers=H)


def test_basic_search_finds_all_files(engine):
    client, read_dir, name = engine
    r = _search(client, read_dir)
    assert r.status_code == 200
    body = r.json()
    assert body["engine"] == name
    found = {os.path.basename(m["path"]) for m in body["matches"]}
    # hidden and gitignored files are searched; symlinks are not followed
    assert found == {"one.txt", "two.py", ".hidden", "ignored.txt", "three.txt"}


def test_ignore_case(engine):
    client, read_dir, _ = engine
    sensitive = {(m["path"], m["line"]) for m in _search(client, read_dir).json()["matches"]}
    insensitive = {
        (m["path"], m["line"])
        for m in _search(client, read_dir, ignore_case=True).json()["matches"]
    }
    assert len(insensitive) == len(sensitive) + 1  # picks up "NEEDLE again"


def test_fixed_strings(engine):
    client, read_dir, _ = engine
    (read_dir / "regex.txt").write_text("literal n.edle text\n")
    r = _search(client, read_dir, query="n.edle", fixed_strings=True)
    found = {os.path.basename(m["path"]) for m in r.json()["matches"]}
    assert found == {"regex.txt"}


def test_glob_filters_by_name(engine):
    client, read_dir, _ = engine
    r = _search(client, read_dir, glob="*.py")
    found = {os.path.basename(m["path"]) for m in r.json()["matches"]}
    assert found == {"two.py"}


def test_max_results_truncates(engine):
    client, read_dir, _ = engine
    r = _search(client, read_dir, max_results=2)
    body = r.json()
    assert len(body["matches"]) == 2
    assert body["truncated"] is True


def test_invalid_regex_400(engine):
    client, read_dir, _ = engine
    r = _search(client, read_dir, query="([unclosed")
    assert r.status_code == 400


@pytest.mark.skipif(not HAS_RG, reason="ripgrep not installed")
def test_engine_parity(env):
    server, client, read_dir = env
    rg = _search(client, read_dir, ignore_case=True).json()
    server.SEARCH_BINARY = None
    py = _search(client, read_dir, ignore_case=True).json()
    assert rg["engine"] == "rg" and py["engine"] == "python"

    def key(match):
        return (match["path"], match["line"], match["text"])

    assert sorted(map(key, rg["matches"])) == sorted(map(key, py["matches"]))


def test_list_dir_entries(env):
    _, client, read_dir = env
    os.symlink(read_dir / "one.txt", read_dir / "link.txt")
    r = client.post("/list-dir", json={"path": str(read_dir)}, headers=H)
    assert r.status_code == 200
    body = r.json()
    entries = {e["name"]: e for e in body["entries"]}
    assert entries["one.txt"]["type"] == "file"
    assert entries["sub"]["type"] == "dir"
    assert entries["link.txt"]["type"] == "symlink"
    names = [e["name"] for e in body["entries"]]
    assert names == sorted(names)
    assert body["truncated"] is False
