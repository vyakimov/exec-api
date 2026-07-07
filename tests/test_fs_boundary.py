"""Filesystem-boundary regression tests.

The prefix checks in can_read / can_list / can_write / can_remove are the
security boundary; every test here is an attempted escape that must fail.
"""

import base64
import os

import pytest
from fastapi.testclient import TestClient

H = {"Authorization": "Bearer tok"}

ALL_OPS = (
    "read_file", "write_file", "copy_uploaded_file", "search_files", "list_dir",
    "delete_file", "move_file",
)


@pytest.fixture
def env(load_server, tmp_path, stub_cmd):
    read_dir = tmp_path / "read"
    write_dir = tmp_path / "write"
    outside = tmp_path / "outside"
    for d in (read_dir, write_dir, outside):
        d.mkdir()
    (read_dir / "a.txt").write_text("alpha needle\n")
    (outside / "secret.txt").write_text("secret needle\n")
    config = {
        "filesystem": {
            "read_prefixes": [str(read_dir)],
            "write_prefixes": [str(write_dir)],
        },
        "operations": dict.fromkeys(ALL_OPS, True),
        "commands": {"ping": {"allowed": True, "executable": stub_cmd}},
    }
    server = load_server(config, {"EXEC_API_TOKEN": "tok"})
    return server, TestClient(server.app), read_dir, write_dir, outside


def test_read_outside_prefix_denied(env):
    _, client, _, _, outside = env
    r = client.post("/read-file", json={"path": f"{outside}/secret.txt"}, headers=H)
    assert r.status_code == 403


def test_read_dotdot_traversal_denied(env):
    _, client, read_dir, _, _ = env
    r = client.post(
        "/read-file", json={"path": f"{read_dir}/../outside/secret.txt"}, headers=H
    )
    assert r.status_code == 403


def test_read_symlink_escape_denied(env):
    _, client, read_dir, _, outside = env
    os.symlink(outside / "secret.txt", read_dir / "link.txt")
    r = client.post("/read-file", json={"path": f"{read_dir}/link.txt"}, headers=H)
    assert r.status_code == 403


def test_read_nonexistent_is_404(env):
    _, client, read_dir, _, _ = env
    r = client.post("/read-file", json={"path": f"{read_dir}/nope.txt"}, headers=H)
    assert r.status_code == 404


def test_list_outside_prefix_denied(env):
    _, client, _, _, outside = env
    r = client.post("/list-dir", json={"path": str(outside)}, headers=H)
    assert r.status_code == 403


def test_list_of_file_is_400(env):
    _, client, read_dir, _, _ = env
    r = client.post("/list-dir", json={"path": f"{read_dir}/a.txt"}, headers=H)
    assert r.status_code == 400


def test_search_root_outside_prefix_denied(env):
    _, client, _, _, outside = env
    r = client.post("/search-files", json={"root": str(outside), "query": "x"}, headers=H)
    assert r.status_code == 403


def test_python_search_does_not_read_through_symlinks(env):
    server, client, read_dir, _, outside = env
    os.symlink(outside / "secret.txt", read_dir / "link.txt")
    server.SEARCH_BINARY = None  # force the fallback engine
    r = client.post("/search-files", json={"root": str(read_dir), "query": "needle"}, headers=H)
    assert r.status_code == 200
    paths = [m["path"] for m in r.json()["matches"]]
    assert any(p.endswith("a.txt") for p in paths)
    assert not any("link" in p for p in paths)


def test_write_outside_prefix_denied(env):
    _, client, _, _, outside = env
    r = client.post(
        "/write-file",
        json={"path": f"{outside}/evil.txt",
              "content_base64": base64.b64encode(b"x").decode()},
        headers=H,
    )
    assert r.status_code == 403


def test_write_through_symlinked_dir_denied(env):
    _, client, _, write_dir, outside = env
    os.symlink(outside, write_dir / "linkdir")
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/linkdir/evil.txt",
              "content_base64": base64.b64encode(b"x").decode()},
        headers=H,
    )
    assert r.status_code == 403
    assert not (outside / "evil.txt").exists()


@pytest.mark.parametrize("mode", ["create", "overwrite", "append"])
def test_write_to_symlink_final_target_denied(env, mode):
    _, client, _, write_dir, outside = env
    target = outside / "target.txt"
    target.write_text("orig")
    os.symlink(target, write_dir / "sneaky.txt")
    r = client.post(
        "/write-file",
        json={"path": f"{write_dir}/sneaky.txt", "mode": mode,
              "content_base64": base64.b64encode(b"evil").decode()},
        headers=H,
    )
    assert r.status_code == 403
    assert target.read_text() == "orig"


def test_write_relative_path_rejected(env):
    _, client, _, _, _ = env
    r = client.post(
        "/write-file", json={"path": "relative.txt", "content_base64": ""}, headers=H
    )
    assert r.status_code == 400


def test_delete_outside_write_prefix_denied(env):
    _, client, read_dir, _, _ = env
    r = client.post("/delete-file", json={"path": f"{read_dir}/a.txt"}, headers=H)
    assert r.status_code == 403
    assert (read_dir / "a.txt").exists()


def test_delete_symlink_removes_link_not_target(env):
    _, client, _, write_dir, outside = env
    target = outside / "keep.txt"
    target.write_text("keep me")
    os.symlink(target, write_dir / "link.txt")
    r = client.post("/delete-file", json={"path": f"{write_dir}/link.txt"}, headers=H)
    assert r.status_code == 200
    assert not (write_dir / "link.txt").is_symlink()
    assert target.read_text() == "keep me"


def test_delete_directory_refused(env):
    _, client, _, write_dir, _ = env
    (write_dir / "subdir").mkdir()
    r = client.post("/delete-file", json={"path": f"{write_dir}/subdir"}, headers=H)
    assert r.status_code == 400
    assert (write_dir / "subdir").is_dir()


def test_move_dest_outside_write_prefix_denied(env):
    _, client, _, write_dir, outside = env
    src = write_dir / "m.txt"
    src.write_text("data")
    r = client.post(
        "/move-file", json={"src": str(src), "dest": f"{outside}/m.txt"}, headers=H
    )
    assert r.status_code == 403
    assert src.exists()


def test_move_symlink_source_refused(env):
    _, client, _, write_dir, outside = env
    target = outside / "t.txt"
    target.write_text("t")
    os.symlink(target, write_dir / "srclink.txt")
    r = client.post(
        "/move-file",
        json={"src": f"{write_dir}/srclink.txt", "dest": f"{write_dir}/out.txt"},
        headers=H,
    )
    assert r.status_code == 400
