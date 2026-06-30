"""Test fixtures for exec-api.

server.py builds all of its config/policy state at import time from a config.yaml
(path overridable via EXEC_API_CONFIG) and the EXEC_API_TOKEN* env vars. To exercise
different policies — and the startup-fatal paths — each scenario reloads the module
fresh with its own config and environment.
"""

import importlib
import os
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _clear_token_env():
    for key in [k for k in os.environ if k.startswith("EXEC_API_TOKEN")]:
        del os.environ[key]


@pytest.fixture
def load_server(tmp_path):
    """Return a function that writes a config and (re)imports server with it.

    The function takes a config dict and an env mapping; it raises SystemExit if
    server's startup validation rejects the config (the _fatal path).
    """
    def _load(config: dict, env: dict):
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.safe_dump(config))
        _clear_token_env()
        os.environ["EXEC_API_CONFIG"] = str(cfg_path)
        os.environ.update(env)
        sys.modules.pop("server", None)
        return importlib.import_module("server")

    yield _load

    sys.modules.pop("server", None)
    _clear_token_env()
    os.environ.pop("EXEC_API_CONFIG", None)


@pytest.fixture
def stub_cmd(tmp_path):
    """Create an executable stub that echoes the YNAB_PROFILE env var, and return
    its path. Used to verify per-command env injection and the command allowlist."""
    path = tmp_path / "stub"
    path.write_text('#!/bin/sh\nprintf "PROFILE=%s\\n" "${YNAB_PROFILE:-unset}"\n')
    path.chmod(0o755)
    return str(path)
