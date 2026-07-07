"""Write/delete/move semantics: modes, mkdirs, size caps, checksums, permissions."""

import base64
import hashlib
import os

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
def env(load_server, tmp_path, stub_cmd):
    read_dir = tmp_path / "read"
    write_dir = tmp_path / "write"
    read_dir.mkdir()
    write_dir.mkdir()
    config = {
        "filesystem": {
            "read_prefixes": [str(read_dir)],
            "write_prefixes": [str(write_dir)],
            "max_write_bytes": 1000,
        },
        "operations": dict.fromkeys(ALL_OPS, True),
        "commands": {"ping": {"allowed": True, "executable": stub_cmd}},
    }
    server = load_server(config, {"EXEC_API_TOKEN": "tok"})
    return server, TestClient(server.app), write_dir


def test_create_then_conflict(env):
    _, client, write_dir = env
    body = {"path": f"{write_dir}/f.txt", "content_base64": _b64(b"one")}
    r = client.post("/write-file", json=body, headers=H)
    assert r.status_code == 200
    assert r.json()["created"] is True
    assert (write_dir / "f.txt").read_bytes() == b"one"

    r = client.post("/write-file", json=body, headers=H)
    assert r.status_code == 409


def test_overwrite_replaces(env):
    _, client, write_dir = env
    (write_dir / "f.txt").write_text("old")
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/f.txt", "content_base64": _b64(b"new"),
              "mode": "overwrite"},
        headers=H,
    )
    assert r.status_code == 200
    assert r.json()["created"] is False
    assert (write_dir / "f.txt").read_bytes() == b"new"


def test_append_accumulates_and_creates(env):
    _, client, write_dir = env
    body = {"path": f"{write_dir}/log.txt", "content_base64": _b64(b"a"), "mode": "append"}
    r = client.post("/write-file", json=body, headers=H)
    assert r.status_code == 200
    assert r.json()["created"] is True
    r = client.post("/write-file", json=body, headers=H)
    assert r.status_code == 200
    assert r.json()["created"] is False
    assert (write_dir / "log.txt").read_bytes() == b"aa"


def test_mkdirs_behaviour(env):
    _, client, write_dir = env
    body = {"path": f"{write_dir}/a/b/c.txt", "content_base64": _b64(b"x")}
    r = client.post("/write-file", json=body, headers=H)
    assert r.status_code == 400  # parent missing, mkdirs off

    r = client.post("/write-file", json={**body, "mkdirs": True}, headers=H)
    assert r.status_code == 200
    assert (write_dir / "a" / "b" / "c.txt").read_bytes() == b"x"


def test_write_size_cap(env):
    _, client, write_dir = env
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/big.txt", "content_base64": _b64(b"x" * 1001)},
        headers=H,
    )
    assert r.status_code == 413


def test_sha256_check(env):
    _, client, write_dir = env
    content = b"checked"
    good = hashlib.sha256(content).hexdigest()
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/s.txt", "content_base64": _b64(content),
              "expected_sha256": good},
        headers=H,
    )
    assert r.status_code == 200
    assert r.json()["sha256"] == good

    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/s2.txt", "content_base64": _b64(content),
              "expected_sha256": "0" * 64},
        headers=H,
    )
    assert r.status_code == 400


def test_invalid_mode_and_bad_base64(env):
    _, client, write_dir = env
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/x", "content_base64": "", "mode": "clobber"},
        headers=H,
    )
    assert r.status_code == 400
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/x", "content_base64": "!!not-base64!!"},
        headers=H,
    )
    assert r.status_code == 400


def test_written_file_mode_matches_umask(env):
    _, client, write_dir = env
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/perm.txt", "content_base64": _b64(b"hi")},
        headers=H,
    )
    assert r.status_code == 200
    umask = os.umask(0)
    os.umask(umask)
    assert ((write_dir / "perm.txt").stat().st_mode & 0o777) == (0o666 & ~umask)


def test_copy_uploaded_file_places_content(env):
    _, client, write_dir = env
    r = client.post(
        "/copy-uploaded-file",
        json={"file": "@file:0", "dest": f"{write_dir}/up.bin",
              "files": [{"name": "up.bin", "content_base64": _b64(b"payload")}]},
        headers=H,
    )
    assert r.status_code == 200
    assert (write_dir / "up.bin").read_bytes() == b"payload"

    r = client.post(
        "/copy-uploaded-file",
        json={"file": "@file:missing", "dest": f"{write_dir}/up2.bin",
              "files": [{"name": "up.bin", "content_base64": _b64(b"payload")}]},
        headers=H,
    )
    assert r.status_code == 404


def test_delete_file(env):
    _, client, write_dir = env
    f = write_dir / "gone.txt"
    f.write_text("bye")
    r = client.post("/delete-file", json={"path": str(f)}, headers=H)
    assert r.status_code == 200
    assert not f.exists()

    r = client.post("/delete-file", json={"path": str(f)}, headers=H)
    assert r.status_code == 404


def test_move_create_overwrite_and_conflict(env):
    _, client, write_dir = env
    (write_dir / "src.txt").write_text("data")
    r = client.post(
        "/move-file",
        json={"src": f"{write_dir}/src.txt", "dest": f"{write_dir}/dst.txt"},
        headers=H,
    )
    assert r.status_code == 200
    assert not (write_dir / "src.txt").exists()
    assert (write_dir / "dst.txt").read_text() == "data"

    (write_dir / "src2.txt").write_text("other")
    r = client.post(
        "/move-file",
        json={"src": f"{write_dir}/src2.txt", "dest": f"{write_dir}/dst.txt"},
        headers=H,
    )
    assert r.status_code == 409  # create mode, dest exists

    r = client.post(
        "/move-file",
        json={"src": f"{write_dir}/src2.txt", "dest": f"{write_dir}/dst.txt",
              "mode": "overwrite"},
        headers=H,
    )
    assert r.status_code == 200
    assert (write_dir / "dst.txt").read_text() == "other"

    r = client.post(
        "/move-file",
        json={"src": f"{write_dir}/nope.txt", "dest": f"{write_dir}/x.txt"},
        headers=H,
    )
    assert r.status_code == 404


def test_ranged_read(env, load_server, tmp_path, stub_cmd):
    server, client, write_dir = env
    read_dir = tmp_path / "read"
    (read_dir / "range.txt").write_bytes(b"ABCDEFGHIJ")

    r = client.post(
        "/read-file",
        json={"path": f"{read_dir}/range.txt", "offset": 3, "length": 4},
        headers=H,
    )
    assert r.status_code == 200
    body = r.json()
    assert base64.b64decode(body["content_base64"]) == b"DEFG"
    assert body["total_size"] == 10
    assert body["eof"] is False

    r = client.post(
        "/read-file", json={"path": f"{read_dir}/range.txt", "offset": 8}, headers=H
    )
    body = r.json()
    assert base64.b64decode(body["content_base64"]) == b"IJ"
    assert body["eof"] is True
