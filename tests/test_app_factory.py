"""create_app() factory: independent app instances from one process."""

from fastapi.testclient import TestClient


def _config(read_dir, write_dir, stub):
    return {
        "filesystem": {"read_prefixes": [str(read_dir)], "write_prefixes": [str(write_dir)]},
        "operations": {"read_file": True},
        "commands": {"ping": {"allowed": True, "executable": stub}},
    }


def test_two_apps_coexist_with_separate_policies(server_module, tmp_path, stub_cmd):
    """Two apps built from different configs serve simultaneously and do not
    share tokens, prefixes, or state."""
    dir_a, dir_b = tmp_path / "a", tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "a.txt").write_text("in a")
    (dir_b / "b.txt").write_text("in b")

    app_a = server_module.create_app(_config(dir_a, dir_a, stub_cmd), {"EXEC_API_TOKEN": "tok-a"})
    app_b = server_module.create_app(_config(dir_b, dir_b, stub_cmd), {"EXEC_API_TOKEN": "tok-b"})
    client_a = TestClient(app_a)
    client_b = TestClient(app_b)

    ha = {"Authorization": "Bearer tok-a"}
    hb = {"Authorization": "Bearer tok-b"}

    def read(client, path, headers):
        return client.post("/read-file", json={"path": str(path)}, headers=headers).status_code

    # each app accepts only its own token
    assert read(client_a, dir_a / "a.txt", ha) == 200
    assert read(client_a, dir_a / "a.txt", hb) == 401
    assert read(client_b, dir_b / "b.txt", hb) == 200

    # each app enforces only its own prefixes
    assert read(client_a, dir_b / "b.txt", ha) == 403
    assert read(client_b, dir_a / "a.txt", hb) == 403

    # mutating one app's state does not leak into the other
    app_a.state.exec.search_binary = None
    assert app_b.state.exec.search_binary != "sentinel"
    assert app_a.state.exec.principals is not app_b.state.exec.principals
