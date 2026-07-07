"""Test fixtures for exec-api.

server.py exposes create_app(config, environ): each test scenario builds a
fresh, independent app from a config dict and an env mapping — no module
reloads, no os.environ mutation for tokens. The module itself is imported once
against a minimal bootstrap config (import-time `app = create_app()` needs one
to exist).
"""

import os
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

_BOOTSTRAP_CONFIG = {"filesystem": {}, "operations": {}, "commands": {}}


@pytest.fixture(scope="session")
def server_module(tmp_path_factory):
    """Import server once against a bootstrap config; scenarios use create_app."""
    cfg_path = tmp_path_factory.mktemp("bootstrap") / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(_BOOTSTRAP_CONFIG))
    os.environ["EXEC_API_CONFIG"] = str(cfg_path)
    os.environ.setdefault("EXEC_API_TOKEN", "bootstrap-token")
    import server
    return server


@pytest.fixture
def load_server(server_module):
    """Return a function that builds a fresh app from a config dict and env mapping.

    Raises SystemExit if startup validation rejects the config (the _fatal
    path). The new app is installed as server.app so TestClient(server.app)
    call sites see the scenario's app; per-app state is on server.app.state.exec.
    """
    def _load(config: dict, env: dict):
        server_module.app = server_module.create_app(config, env)
        return server_module

    return _load


@pytest.fixture
def stub_cmd(tmp_path):
    """Create an executable stub that echoes the YNAB_PROFILE env var, and return
    its path. Used to verify per-command env injection and the command allowlist."""
    path = tmp_path / "stub"
    path.write_text('#!/bin/sh\nprintf "PROFILE=%s\\n" "${YNAB_PROFILE:-unset}"\n')
    path.chmod(0o755)
    return str(path)
