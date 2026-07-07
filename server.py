"""exec-api — policy-checked filesystem operations and allowlisted commands over HTTP.

Operations (read/write/list/search) are the security boundary: every filesystem
touch goes through can_read/can_write/can_list, which check resolved paths against
the prefixes in config.yaml. The binary allowlist under `commands` is only a last
line of defense, backed by a hard denylist of code-execution-capable binaries.
"""

import asyncio
import base64
import fnmatch
import hashlib
import hmac
import logging
import mimetypes
import os
import re
import shutil
import signal
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("exec-api")


def _fatal(msg: str) -> None:
    print(f"FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


# --- Limits ---
COMMAND_TIMEOUT = 30  # seconds
STDIN_MAX_BYTES = 256 * 1024  # 256 KiB
SUPPORTED_STDIN_ENCODINGS = frozenset({"utf-8"})
FILES_MAX_COUNT = 8
FILE_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
FILES_TOTAL_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
FILENAME_MAX_CHARS = 128
FILE_PLACEHOLDER_PREFIX = "@file:"
FILESDIR_PLACEHOLDER = "@filesdir"

WRITE_MODES = frozenset({"create", "overwrite", "append"})
SEARCH_MAX_MATCHES = 2000
LIST_MAX_ENTRIES = 5000

# Binaries that can execute arbitrary programs or otherwise escape the allowlist.
# These are refused at load even if listed with allowed: true. See README
# "Allowlist hazards".
DENIED_COMMANDS = frozenset({
    "osascript",
    "ssh", "sftp", "scp", "rsync",
    "sh", "bash", "zsh", "dash", "fish", "csh", "tcsh", "ksh",
    "python", "python2", "python3", "perl", "ruby", "node", "deno", "bun", "php", "lua",
    "find", "fd", "xargs", "env", "nice", "nohup", "time", "timeout", "parallel",
    "awk", "gawk", "sed", "make", "cmake", "ninja",
    "git", "hg", "svn",
    "vim", "vi", "nvim", "emacs", "less", "more", "man", "gdb", "lldb",
    "tar", "zip", "unzip", "nc", "ncat", "socat", "tmux", "screen", "expect",
})


# --- Configuration (config.yaml) ---
# EXEC_API_CONFIG overrides the config path (used by the test suite); defaults to
# config.yaml next to this file.
CONFIG_PATH = Path(
    os.environ.get("EXEC_API_CONFIG") or Path(__file__).resolve().parent / "config.yaml"
)


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        _fatal(
            f"config.yaml not found at {CONFIG_PATH}. Copy config.yaml.example "
            "to config.yaml and edit it."
        )
    try:
        data = yaml.safe_load(CONFIG_PATH.read_text())
    except yaml.YAMLError as exc:
        _fatal(f"config.yaml is not valid YAML: {exc}")
    if not isinstance(data, dict):
        _fatal("config.yaml must be a mapping")
    return data


CONFIG: dict = _load_config()


def _resolve_prefixes(raw_list, label: str) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for candidate in raw_list or []:
        try:
            resolved.append(Path(str(candidate)).expanduser().resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            print(
                f"warning: {label} prefix '{candidate}' unavailable: {exc}",
                file=sys.stderr,
            )
    return tuple(resolved)


_FS = CONFIG.get("filesystem") or {}
READ_PREFIXES: tuple[Path, ...] = _resolve_prefixes(_FS.get("read_prefixes"), "read")
WRITE_PREFIXES: tuple[Path, ...] = _resolve_prefixes(_FS.get("write_prefixes"), "write")
MAX_READ_BYTES = int(_FS.get("max_read_bytes", 10 * 1024 * 1024))
MAX_WRITE_BYTES = int(_FS.get("max_write_bytes", 10 * 1024 * 1024))
ALLOW_SYMLINK_TARGET = bool(_FS.get("allow_symlink_final_target", False))

_OPS = CONFIG.get("operations") or {}
OPERATION_NAMES = ("read_file", "write_file", "copy_uploaded_file", "search_files", "list_dir")
OPERATIONS: dict[str, bool] = {name: bool(_OPS.get(name, False)) for name in OPERATION_NAMES}

if any(OPERATIONS[o] for o in ("read_file", "list_dir", "search_files")) and not READ_PREFIXES:
    _fatal("read/list/search operations are enabled but no usable read_prefixes are configured")
if (OPERATIONS["write_file"] or OPERATIONS["copy_uploaded_file"]) and not WRITE_PREFIXES:
    _fatal("write operations are enabled but no usable write_prefixes are configured")


def _build_command_paths(commands) -> dict[str, str]:
    paths: dict[str, str] = {}
    for name, spec in (commands or {}).items():
        spec = spec or {}
        if not spec.get("allowed", False):
            continue
        if name in DENIED_COMMANDS:
            print(
                f"warning: command '{name}' is on the hard denylist and will not be "
                "registered, even though config marks it allowed",
                file=sys.stderr,
            )
            continue
        exe = spec.get("executable")
        if exe and not Path(exe).exists():
            print(
                f"warning: executable for '{name}' missing at {exe}, falling back to PATH",
                file=sys.stderr,
            )
            exe = None
        if exe is None:
            exe = shutil.which(name)
        if exe:
            paths[name] = exe
        else:
            print(f"warning: '{name}' not found, will be unavailable", file=sys.stderr)
    return paths


COMMAND_PATHS: dict[str, str] = _build_command_paths(CONFIG.get("commands"))

# Internal search engine (independent of the allowlist). Prefer ripgrep; fall
# back to a pure-Python walk if rg is unavailable.
_SEARCH_CFG = CONFIG.get("search_binary")
SEARCH_BINARY: str | None = (
    _SEARCH_CFG if (_SEARCH_CFG and Path(_SEARCH_CFG).exists()) else shutil.which("rg")
)

# --- Principals (token -> identity -> policy) ---
#
# Each bearer token maps to a named principal carrying its own policy: filesystem
# prefixes, operation toggles, and the subset of the command registry it may run
# (with optional per-command environment overrides). The top-level
# filesystem/operations/commands blocks above are the "default" policy that
# `inherit_default` reuses and that legacy (no `auth:` section) mode applies to a
# single implicit owner.
INHERIT = "inherit_default"


@dataclass(frozen=True)
class Principal:
    name: str
    read_prefixes: tuple[Path, ...]
    write_prefixes: tuple[Path, ...]
    operations: dict[str, bool]
    commands: dict[str, str]  # command name -> resolved executable path
    command_env: dict[str, dict[str, str]] = field(default_factory=dict)


def _policy_filesystem(name: str, spec) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    if spec is None or spec == INHERIT:
        return READ_PREFIXES, WRITE_PREFIXES
    if not isinstance(spec, dict):
        _fatal(f"policy '{name}': filesystem must be a mapping or '{INHERIT}'")
    reads = _resolve_prefixes(spec.get("read_prefixes"), f"{name} read")
    writes = _resolve_prefixes(spec.get("write_prefixes"), f"{name} write")
    return reads, writes


def _policy_operations(name: str, spec) -> dict[str, bool]:
    if spec is None or spec == INHERIT:
        return dict(OPERATIONS)
    if not isinstance(spec, dict):
        _fatal(f"policy '{name}': operations must be a mapping or '{INHERIT}'")
    return {op: bool(spec.get(op, False)) for op in OPERATION_NAMES}


def _policy_commands(name: str, spec) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    if spec is None or spec == INHERIT:
        return dict(COMMAND_PATHS), {}
    if not isinstance(spec, dict):
        _fatal(f"policy '{name}': commands must be a mapping or '{INHERIT}'")
    commands: dict[str, str] = {}
    command_env: dict[str, dict[str, str]] = {}
    for cmd, cmd_spec in spec.items():
        if cmd not in COMMAND_PATHS:
            _fatal(
                f"policy '{name}': command '{cmd}' is not an allowed, resolvable entry "
                "in the top-level `commands` registry"
            )
        commands[cmd] = COMMAND_PATHS[cmd]
        cmd_spec = cmd_spec or {}
        env = cmd_spec.get("env") or {}
        if env:
            if not isinstance(env, dict):
                _fatal(f"policy '{name}': env for command '{cmd}' must be a mapping")
            command_env[cmd] = {str(k): str(v) for k, v in env.items()}
    return commands, command_env


def _validate_principal_policy(p: Principal) -> None:
    reads_enabled = any(p.operations[o] for o in ("read_file", "list_dir", "search_files"))
    if reads_enabled and not p.read_prefixes:
        _fatal(
            f"policy for principal '{p.name}' enables read/list/search but has no usable "
            "read_prefixes"
        )
    if (p.operations["write_file"] or p.operations["copy_uploaded_file"]) and not p.write_prefixes:
        _fatal(
            f"policy for principal '{p.name}' enables write/copy but has no usable "
            "write_prefixes"
        )


def _build_principals() -> dict[str, Principal]:
    auth = CONFIG.get("auth")

    # Legacy mode: no `auth:` section -> single implicit owner from EXEC_API_TOKEN
    # with the top-level (default) policy. Behaviour is identical to before.
    if not auth:
        token = os.environ.get("EXEC_API_TOKEN", "")
        if not token:
            _fatal("EXEC_API_TOKEN not set")
        owner = Principal(
            name="owner",
            read_prefixes=READ_PREFIXES,
            write_prefixes=WRITE_PREFIXES,
            operations=dict(OPERATIONS),
            commands=dict(COMMAND_PATHS),
        )
        return {token: owner}

    if not isinstance(auth, dict):
        _fatal("config.yaml: `auth` must be a mapping")
    tokens_cfg = auth.get("tokens")
    if not isinstance(tokens_cfg, dict) or not tokens_cfg:
        _fatal("config.yaml: `auth.tokens` must be a non-empty mapping")
    policies_cfg = CONFIG.get("policies") or {}
    if not isinstance(policies_cfg, dict):
        _fatal("config.yaml: `policies` must be a mapping")

    principals: dict[str, Principal] = {}
    for name, tok_spec in tokens_cfg.items():
        tok_spec = tok_spec or {}
        env_name = tok_spec.get("env")
        if not env_name:
            _fatal(f"auth.tokens.{name}: missing `env` (the env var holding the token)")
        token = os.environ.get(env_name, "")
        if not token:
            _fatal(f"auth.tokens.{name}: env var {env_name} is not set or empty")
        if token in principals:
            _fatal(
                f"auth.tokens.{name}: token value collides with another principal "
                "(two principals share the same token)"
            )

        policy_name = tok_spec.get("policy")
        if not policy_name:
            _fatal(f"auth.tokens.{name}: missing `policy`")
        if policy_name not in policies_cfg:
            _fatal(f"auth.tokens.{name}: policy '{policy_name}' not found under `policies`")
        policy = policies_cfg[policy_name] or {}
        if not isinstance(policy, dict):
            _fatal(f"policies.{policy_name}: must be a mapping")

        reads, writes = _policy_filesystem(name, policy.get("filesystem"))
        operations = _policy_operations(name, policy.get("operations"))
        commands, command_env = _policy_commands(name, policy.get("commands"))
        principal = Principal(
            name=name,
            read_prefixes=reads,
            write_prefixes=writes,
            operations=operations,
            commands=commands,
            command_env=command_env,
        )
        _validate_principal_policy(principal)
        principals[token] = principal

    return principals


PRINCIPALS: dict[str, Principal] = _build_principals()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# --- Request models ---
class InputFile(BaseModel):
    name: str = Field(min_length=1, max_length=FILENAME_MAX_CHARS)
    content_base64: str = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        candidate = Path(value)
        if candidate.name != value:
            raise ValueError("file name must not contain path separators")
        if value in {".", ".."}:
            raise ValueError("file name must not be '.' or '..'")
        return value


class ReadFileRequest(BaseModel):
    path: str = Field(min_length=1)


class WriteFileRequest(BaseModel):
    path: str = Field(min_length=1)
    content_base64: str = ""
    mode: str = "create"
    mkdirs: bool = False
    expected_sha256: str | None = None


class CopyUploadedFileRequest(BaseModel):
    file: str = Field(min_length=1)
    dest: str = Field(min_length=1)
    mode: str = "create"
    mkdirs: bool = False
    files: list[InputFile] = Field(default_factory=list, max_length=FILES_MAX_COUNT)


class SearchFilesRequest(BaseModel):
    root: str = Field(min_length=1)
    query: str = Field(min_length=1)
    glob: str | None = None
    ignore_case: bool = False
    fixed_strings: bool = False
    max_results: int = 1000


class ListDirRequest(BaseModel):
    path: str = Field(min_length=1)


class RunRequest(BaseModel):
    command: str
    args: list[str] = []
    stdin_text: str | None = None
    stdin_encoding: str = "utf-8"
    files: list[InputFile] = Field(default_factory=list, max_length=FILES_MAX_COUNT)


# --- File upload staging ---
def decode_input_file(upload: InputFile) -> bytes:
    try:
        content = base64.b64decode(upload.content_base64, validate=True)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"invalid base64 content for file '{upload.name}'",
        ) from exc
    if len(content) > FILE_MAX_BYTES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"file '{upload.name}' too large "
                f"({len(content)} bytes, max {FILE_MAX_BYTES})"
            ),
        )
    return content


def stage_input_files(files: list[InputFile]) -> tuple[Path | None, list[Path], int]:
    if not files:
        return None, [], 0

    decoded_files: list[tuple[InputFile, bytes]] = []
    seen_names: set[str] = set()
    total_bytes = 0
    for upload in files:
        if upload.name in seen_names:
            raise HTTPException(
                status_code=400,
                detail=f"duplicate uploaded file name: {upload.name}",
            )
        seen_names.add(upload.name)
        content = decode_input_file(upload)
        total_bytes += len(content)
        if total_bytes > FILES_TOTAL_MAX_BYTES:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"files too large in total ({total_bytes} bytes, "
                    f"max {FILES_TOTAL_MAX_BYTES})"
                ),
            )
        decoded_files.append((upload, content))

    temp_dir = Path(tempfile.mkdtemp(prefix="exec-api-"))
    staged_paths: list[Path] = []
    try:
        for upload, content in decoded_files:
            target_path = temp_dir / upload.name
            with target_path.open("xb") as fh:
                fh.write(content)
            staged_paths.append(target_path)
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail=f"failed to stage uploaded files: {exc}",
        ) from exc

    return temp_dir, staged_paths, total_bytes


def inject_file_args(
    args: list[str], staged_paths: list[Path], temp_dir: Path | None
) -> list[str]:
    if not staged_paths:
        return args

    replacements_by_index = {
        f"{FILE_PLACEHOLDER_PREFIX}{index}": str(path)
        for index, path in enumerate(staged_paths)
    }
    replacements_by_name = {
        f"{FILE_PLACEHOLDER_PREFIX}{path.name}": str(path) for path in staged_paths
    }

    injected_args: list[str] = []
    referenced_indices: set[int] = set()
    referenced_names: set[str] = set()

    for arg in args:
        if arg == FILESDIR_PLACEHOLDER:
            injected_args.append(str(temp_dir))
            continue
        if arg in replacements_by_index:
            injected_args.append(replacements_by_index[arg])
            referenced_indices.add(int(arg.removeprefix(FILE_PLACEHOLDER_PREFIX)))
            continue
        if arg in replacements_by_name:
            injected_args.append(replacements_by_name[arg])
            referenced_names.add(arg.removeprefix(FILE_PLACEHOLDER_PREFIX))
            continue
        injected_args.append(arg)

    for index, path in enumerate(staged_paths):
        if index in referenced_indices or path.name in referenced_names:
            continue
        injected_args.append(str(path))

    return injected_args


def _resolve_file_ref(ref: str, staged_paths: list[Path]) -> Path:
    """Resolve a `@file:0` / `@file:name` / `0` / `name` reference to a staged path."""
    key = ref.removeprefix(FILE_PLACEHOLDER_PREFIX)
    if key.isdigit():
        idx = int(key)
        if 0 <= idx < len(staged_paths):
            return staged_paths[idx]
    for path in staged_paths:
        if path.name == key:
            return path
    raise HTTPException(status_code=404, detail=f"uploaded file not found: {ref}")


# --- Auth + policy ---
def _check_auth(authorization: str) -> Principal:
    token = authorization.removeprefix("Bearer ").strip()
    # Compare against every principal's token without early-exit so the match is
    # constant-time with respect to which (or whether a) principal matched.
    matched: Principal | None = None
    for tok, principal in PRINCIPALS.items():
        if hmac.compare_digest(token, tok):
            matched = principal
    if matched is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    return matched


def _require_operation(principal: Principal, name: str) -> None:
    if not principal.operations.get(name, False):
        raise HTTPException(status_code=404, detail=f"operation not enabled: {name}")


def _under_prefixes(resolved: Path, prefixes: tuple[Path, ...]) -> bool:
    for prefix in prefixes:
        try:
            resolved.relative_to(prefix)
            return True
        except ValueError:
            continue
    return False


def _canonical_existing(raw_path: str) -> Path:
    try:
        return Path(raw_path).expanduser().resolve(strict=True)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="path not found") from None
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid path: {exc}") from exc


def can_read(principal: Principal, raw_path: str) -> Path:
    resolved = _canonical_existing(raw_path)
    allowed = _under_prefixes(resolved, principal.read_prefixes)
    logger.info(
        "policy principal=%s op=read original=%s resolved=%s decision=%s",
        principal.name, raw_path, resolved, "allow" if allowed else "deny",
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="path outside allowed read prefixes")
    return resolved


def can_list(principal: Principal, raw_path: str) -> Path:
    resolved = _canonical_existing(raw_path)
    allowed = _under_prefixes(resolved, principal.read_prefixes)
    logger.info(
        "policy principal=%s op=list original=%s resolved=%s decision=%s",
        principal.name, raw_path, resolved, "allow" if allowed else "deny",
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="path outside allowed read prefixes")
    if not resolved.is_dir():
        raise HTTPException(status_code=400, detail="path is not a directory")
    return resolved


def can_write(principal: Principal, raw_path: str, *, mkdirs: bool) -> Path:
    """Resolve a write destination and enforce the write policy.

    Resolves the deepest existing ancestor (following symlinks) so a symlinked
    directory cannot escape the write prefixes, then composes the destination
    from the remaining (non-existent) path components.
    """
    p = Path(raw_path).expanduser()
    if not p.is_absolute():
        raise HTTPException(status_code=400, detail="write path must be absolute")

    ancestor = p.parent
    rel_parts = [p.name]
    while not ancestor.exists():
        rel_parts.append(ancestor.name)
        if ancestor.parent == ancestor:
            raise HTTPException(status_code=400, detail="invalid path")
        ancestor = ancestor.parent

    try:
        real_ancestor = ancestor.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid path: {exc}") from exc

    dest = real_ancestor.joinpath(*reversed(rel_parts))
    parent_exists = dest.parent.exists()
    if not parent_exists and not mkdirs:
        raise HTTPException(
            status_code=400, detail="parent directory does not exist (set mkdirs)"
        )

    allowed = _under_prefixes(dest, principal.write_prefixes)
    logger.info(
        "policy principal=%s op=write original=%s resolved=%s decision=%s",
        principal.name, raw_path, dest, "allow" if allowed else "deny",
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="path outside allowed write prefixes")
    if dest.is_dir():
        raise HTTPException(status_code=400, detail="destination is a directory")
    if dest.is_symlink() and not ALLOW_SYMLINK_TARGET:
        raise HTTPException(status_code=403, detail="destination is a symlink")
    return dest


def _place_file(content: bytes, dest: Path, mode: str, mkdirs: bool) -> bool:
    """Write content to dest atomically. Returns True if a new file was created."""
    if mkdirs:
        dest.parent.mkdir(parents=True, exist_ok=True)

    if mode == "append":
        created = not dest.exists()
        with open(dest, "ab") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        return created

    fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent), prefix=".exec-api-tmp-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        if mode == "create":
            try:
                os.link(tmp, dest)
            except FileExistsError as exc:
                raise HTTPException(
                    status_code=409,
                    detail="destination already exists (use mode=overwrite)",
                ) from exc
            return True
        existed = dest.exists()
        os.replace(tmp, dest)
        return not existed
    finally:
        if tmp.exists():
            tmp.unlink()


# --- Endpoints ---
@app.post("/read-file")
async def read_file(req: ReadFileRequest, authorization: str = Header()):
    principal = _check_auth(authorization)
    _require_operation(principal, "read_file")

    resolved = can_read(principal, req.path)
    if not resolved.is_file():
        raise HTTPException(status_code=400, detail="path is not a regular file")

    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"stat failed: {exc}") from exc
    if size > MAX_READ_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large ({size} bytes, max {MAX_READ_BYTES})",
        )

    t0 = time.monotonic()
    try:
        content = resolved.read_bytes()
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"read failed: {exc}") from exc
    exec_ms = round((time.monotonic() - t0) * 1000)

    mime, _ = mimetypes.guess_type(resolved.name)
    logger.info("read_file path=%s size=%s exec_ms=%s", resolved, len(content), exec_ms)

    return {
        "name": resolved.name,
        "path": str(resolved),
        "size": len(content),
        "mime": mime,
        "content_base64": base64.b64encode(content).decode("ascii"),
        "exec_ms": exec_ms,
    }


@app.post("/write-file")
async def write_file(req: WriteFileRequest, authorization: str = Header()):
    principal = _check_auth(authorization)
    _require_operation(principal, "write_file")

    if req.mode not in WRITE_MODES:
        raise HTTPException(status_code=400, detail=f"invalid mode: {req.mode}")

    try:
        content = base64.b64decode(req.content_base64, validate=True) if req.content_base64 else b""
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid base64 content") from exc
    if len(content) > MAX_WRITE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"content too large ({len(content)} bytes, max {MAX_WRITE_BYTES})",
        )

    sha = hashlib.sha256(content).hexdigest()
    if req.expected_sha256 and req.expected_sha256.lower() != sha:
        raise HTTPException(status_code=400, detail="content sha256 mismatch")

    dest = can_write(principal, req.path, mkdirs=req.mkdirs)

    t0 = time.monotonic()
    try:
        created = _place_file(content, dest, req.mode, req.mkdirs)
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"write failed: {exc}") from exc
    exec_ms = round((time.monotonic() - t0) * 1000)

    logger.info(
        "write_file path=%s size=%s mode=%s created=%s exec_ms=%s",
        dest, len(content), req.mode, created, exec_ms,
    )
    return {
        "path": str(dest),
        "size": len(content),
        "sha256": sha,
        "created": created,
        "exec_ms": exec_ms,
    }


@app.post("/copy-uploaded-file")
async def copy_uploaded_file(req: CopyUploadedFileRequest, authorization: str = Header()):
    principal = _check_auth(authorization)
    _require_operation(principal, "copy_uploaded_file")

    if req.mode not in WRITE_MODES:
        raise HTTPException(status_code=400, detail=f"invalid mode: {req.mode}")
    if not req.files:
        raise HTTPException(status_code=400, detail="no uploaded files provided")

    temp_dir, staged_paths, _ = stage_input_files(req.files)
    t0 = time.monotonic()
    try:
        src = _resolve_file_ref(req.file, staged_paths)
        content = src.read_bytes()
        if len(content) > MAX_WRITE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"content too large ({len(content)} bytes, max {MAX_WRITE_BYTES})",
            )
        dest = can_write(principal, req.dest, mkdirs=req.mkdirs)
        created = _place_file(content, dest, req.mode, req.mkdirs)
        sha = hashlib.sha256(content).hexdigest()
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"copy failed: {exc}") from exc
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)
    exec_ms = round((time.monotonic() - t0) * 1000)

    logger.info(
        "copy_uploaded_file dest=%s size=%s mode=%s created=%s exec_ms=%s",
        dest, len(content), req.mode, created, exec_ms,
    )
    return {
        "path": str(dest),
        "size": len(content),
        "sha256": sha,
        "created": created,
        "exec_ms": exec_ms,
    }


async def _search_with_rg(
    root: Path, req: SearchFilesRequest, max_results: int
) -> tuple[list[dict], bool]:
    args = ["--line-number", "--no-heading", "--color", "never", "--with-filename"]
    if req.ignore_case:
        args.append("--ignore-case")
    if req.fixed_strings:
        args.append("--fixed-strings")
    if req.glob:
        args += ["--glob", req.glob]
    # query and root are passed positionally after `--` so they can never be
    # interpreted as flags.
    args += ["--", req.query, str(root)]

    proc = await asyncio.create_subprocess_exec(
        SEARCH_BINARY,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, _stderr = await asyncio.wait_for(
            proc.communicate(), timeout=COMMAND_TIMEOUT
        )
    except TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        await proc.wait()
        raise HTTPException(status_code=408, detail="search timed out") from None

    matches: list[dict] = []
    truncated = False
    for line in stdout.decode(errors="replace").splitlines():
        if not line:
            continue
        if len(matches) >= max_results:
            truncated = True
            break
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[1].isdigit():
            matches.append({"path": parts[0], "line": int(parts[1]), "text": parts[2]})
        else:
            matches.append({"path": None, "line": None, "text": line})
    return matches, truncated


def _search_with_python(
    root: Path, req: SearchFilesRequest, max_results: int
) -> tuple[list[dict], bool]:
    flags = re.IGNORECASE if req.ignore_case else 0
    if req.fixed_strings:
        pattern = re.compile(re.escape(req.query), flags)
    else:
        try:
            pattern = re.compile(req.query, flags)
        except re.error as exc:
            raise HTTPException(status_code=400, detail=f"invalid query regex: {exc}") from exc

    matches: list[dict] = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if req.glob and not fnmatch.fnmatch(fn, req.glob):
                continue
            fpath = Path(dirpath) / fn
            try:
                with open(fpath, errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if pattern.search(line):
                            if len(matches) >= max_results:
                                return matches, True
                            matches.append(
                                {"path": str(fpath), "line": lineno, "text": line.rstrip("\n")}
                            )
            except OSError:
                continue
    return matches, False


@app.post("/search-files")
async def search_files(req: SearchFilesRequest, authorization: str = Header()):
    principal = _check_auth(authorization)
    _require_operation(principal, "search_files")

    root = can_list(principal, req.root)
    max_results = max(1, min(req.max_results, SEARCH_MAX_MATCHES))

    t0 = time.monotonic()
    if SEARCH_BINARY:
        matches, truncated = await _search_with_rg(root, req, max_results)
        engine = "rg"
    else:
        matches, truncated = _search_with_python(root, req, max_results)
        engine = "python"
    exec_ms = round((time.monotonic() - t0) * 1000)

    logger.info(
        "search_files root=%s engine=%s matches=%s truncated=%s exec_ms=%s",
        root, engine, len(matches), truncated, exec_ms,
    )
    return {
        "root": str(root),
        "matches": matches,
        "truncated": truncated,
        "engine": engine,
        "exec_ms": exec_ms,
    }


@app.post("/list-dir")
async def list_dir(req: ListDirRequest, authorization: str = Header()):
    principal = _check_auth(authorization)
    _require_operation(principal, "list_dir")

    target = can_list(principal, req.path)

    t0 = time.monotonic()
    entries: list[dict] = []
    truncated = False
    try:
        with os.scandir(target) as it:
            for entry in it:
                if len(entries) >= LIST_MAX_ENTRIES:
                    truncated = True
                    break
                try:
                    if entry.is_symlink():
                        etype = "symlink"
                    elif entry.is_dir():
                        etype = "dir"
                    elif entry.is_file():
                        etype = "file"
                    else:
                        etype = "other"
                    st = entry.stat(follow_symlinks=False)
                    entries.append(
                        {
                            "name": entry.name,
                            "type": etype,
                            "size": st.st_size,
                            "mtime": round(st.st_mtime),
                        }
                    )
                except OSError:
                    continue
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"list failed: {exc}") from exc
    exec_ms = round((time.monotonic() - t0) * 1000)

    entries.sort(key=lambda e: e["name"])
    logger.info(
        "list_dir path=%s entries=%s truncated=%s exec_ms=%s",
        target, len(entries), truncated, exec_ms,
    )
    return {
        "path": str(target),
        "entries": entries,
        "truncated": truncated,
        "exec_ms": exec_ms,
    }


@app.post("/run")
async def run_command(req: RunRequest, authorization: str = Header()):
    principal = _check_auth(authorization)

    # Allowlist check (scoped to this principal's policy)
    if req.command not in principal.commands:
        raise HTTPException(
            status_code=403, detail=f"command not allowed: {req.command}"
        )

    # Validate stdin fields
    stdin_bytes: bytes | None = None
    if req.stdin_text is not None:
        if req.stdin_encoding not in SUPPORTED_STDIN_ENCODINGS:
            raise HTTPException(
                status_code=400,
                detail=f"unsupported stdin_encoding: {req.stdin_encoding}",
            )
        stdin_bytes = req.stdin_text.encode(req.stdin_encoding)
        if len(stdin_bytes) > STDIN_MAX_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"stdin_text too large ({len(stdin_bytes)} bytes, max {STDIN_MAX_BYTES})",
            )

    temp_dir: Path | None = None
    staged_paths: list[Path] = []
    staged_file_bytes = 0
    if req.files:
        logger.info(
            "staging_files command=%s file_count=%s",
            req.command,
            len(req.files),
        )
        temp_dir, staged_paths, staged_file_bytes = stage_input_files(req.files)
        logger.info(
            "staged_files command=%s temp_dir=%s file_count=%s file_bytes=%s",
            req.command,
            temp_dir,
            len(staged_paths),
            staged_file_bytes,
        )

    injected_args = inject_file_args(req.args, staged_paths, temp_dir)

    # Run the command. The child inherits the server environment with the
    # principal's per-command overrides layered on top (e.g. YNAB_PROFILE=emma).
    # Note: env= replaces the environment wholesale, so we must merge rather than
    # pass overrides alone, or PATH/HOME and friends would be lost.
    abs_path = principal.commands[req.command]
    child_env = {**os.environ, **principal.command_env.get(req.command, {})}
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            abs_path,
            *injected_args,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=child_env,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout=COMMAND_TIMEOUT
        )
    except TimeoutError:
        # Kill the whole process group so children spawned by the command
        # (e.g. via xargs/make) don't outlive the request.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        await proc.wait()
        raise HTTPException(status_code=408, detail="command timed out") from None
    except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
        # The command is allow-listed but its executable is missing or not
        # runnable at the configured path. Surface an actionable error instead
        # of an opaque 500.
        logger.error(
            "command=%s executable_unrunnable path=%s error=%s",
            req.command,
            abs_path,
            exc,
        )
        raise HTTPException(
            status_code=502,
            detail=(
                f"command '{req.command}' is allow-listed but its executable "
                f"could not be run at '{abs_path}': {exc.strerror or exc}. "
                "Check the 'executable' path in exec-api config.yaml."
            ),
        ) from exc
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(
                "cleanup_files command=%s temp_dir=%s removed=%s",
                req.command,
                temp_dir,
                not temp_dir.exists(),
            )
    exec_ms = round((time.monotonic() - t0) * 1000)

    logger.info(
        "command=%s principal=%s exit_code=%s stdin_bytes=%s file_count=%s "
        "file_bytes=%s exec_ms=%s",
        req.command,
        principal.name,
        proc.returncode,
        len(stdin_bytes) if stdin_bytes is not None else 0,
        len(staged_paths),
        staged_file_bytes,
        exec_ms,
    )

    return {
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "code": proc.returncode,
        "exec_ms": exec_ms,
    }
