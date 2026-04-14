"""exec-api — runs allowlisted commands over HTTP with bearer-token auth."""

import asyncio
import base64
import hmac
import logging
import mimetypes
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("exec-api")

# --- Allowlist (loaded from allowlist.txt, falls back to minimal default) ---
def _load_allowlist() -> frozenset[str]:
    path = Path(__file__).resolve().parent / "allowlist.txt"
    if path.exists():
        cmds = set()
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                cmds.add(line)
        return frozenset(cmds)
    print("warning: allowlist.txt not found, using minimal default", file=sys.stderr)
    return frozenset({"cat", "ls", "echo", "date"})


ALLOWED_COMMANDS: frozenset[str] = _load_allowlist()

COMMAND_TIMEOUT = 30  # seconds
STDIN_MAX_BYTES = 256 * 1024  # 256 KiB
SUPPORTED_STDIN_ENCODINGS = frozenset({"utf-8"})
FILES_MAX_COUNT = 8
FILE_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
FILES_TOTAL_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
FILENAME_MAX_CHARS = 128
FILE_PLACEHOLDER_PREFIX = "@file:"
FILESDIR_PLACEHOLDER = "@filesdir"

READ_FILE_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB


def _load_read_prefixes() -> tuple[Path, ...]:
    raw = os.environ.get("EXEC_API_READ_PREFIXES", "").strip()
    if raw:
        candidates = [p for p in raw.split(":") if p]
    else:
        home = os.environ.get("HOME", "").strip()
        if not home:
            print("FATAL: HOME not set and EXEC_API_READ_PREFIXES not configured", file=sys.stderr)
            sys.exit(1)
        candidates = [home]
    resolved: list[Path] = []
    for c in candidates:
        try:
            resolved.append(Path(c).expanduser().resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            print(f"warning: read prefix '{c}' unavailable: {exc}", file=sys.stderr)
    if not resolved:
        print("FATAL: no usable read-file prefixes", file=sys.stderr)
        sys.exit(1)
    return tuple(resolved)


READ_FILE_PREFIXES: tuple[Path, ...] = _load_read_prefixes()

def _load_command_paths() -> dict[str, str]:
    path = Path(__file__).resolve().parent / "command-paths.json"
    if path.exists():
        import json as _json
        return _json.loads(path.read_text())
    return {}


INTERNAL_COMMAND_PATHS: dict[str, str] = _load_command_paths()

# --- Resolve commands to absolute paths at startup ---
COMMAND_PATHS: dict[str, str] = {}
for cmd in ALLOWED_COMMANDS:
    path = INTERNAL_COMMAND_PATHS.get(cmd)
    if path and not Path(path).exists():
        print(
            f"warning: internal command '{cmd}' missing at {path}, falling back to PATH",
            file=sys.stderr,
        )
        path = None
    if path is None:
        path = shutil.which(cmd)
    if path:
        COMMAND_PATHS[cmd] = path
    else:
        print(
            f"warning: '{cmd}' not found in PATH, will be unavailable", file=sys.stderr
        )

# --- Auth ---
API_TOKEN = os.environ.get("EXEC_API_TOKEN", "")
if not API_TOKEN:
    print("FATAL: EXEC_API_TOKEN not set", file=sys.stderr)
    sys.exit(1)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


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


class RunRequest(BaseModel):
    command: str
    args: list[str] = []
    stdin_text: Optional[str] = None
    stdin_encoding: str = "utf-8"
    files: list[InputFile] = Field(default_factory=list, max_length=FILES_MAX_COUNT)


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


def stage_input_files(files: list[InputFile]) -> tuple[Optional[Path], list[Path], int]:
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
    args: list[str], staged_paths: list[Path], temp_dir: Optional[Path]
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


def _check_auth(authorization: str) -> None:
    token = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(token, API_TOKEN):
        raise HTTPException(status_code=401, detail="unauthorized")


def _resolve_under_prefix(raw_path: str) -> Path:
    try:
        resolved = Path(raw_path).expanduser().resolve(strict=True)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="file not found")
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid path: {exc}") from exc
    for prefix in READ_FILE_PREFIXES:
        try:
            resolved.relative_to(prefix)
        except ValueError:
            continue
        return resolved
    raise HTTPException(status_code=403, detail="path outside allowed prefixes")


@app.post("/read-file")
async def read_file(req: ReadFileRequest, authorization: str = Header()):
    _check_auth(authorization)

    resolved = _resolve_under_prefix(req.path)
    if not resolved.is_file():
        raise HTTPException(status_code=400, detail="path is not a regular file")

    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"stat failed: {exc}") from exc
    if size > READ_FILE_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large ({size} bytes, max {READ_FILE_MAX_BYTES})",
        )

    t0 = time.monotonic()
    try:
        content = resolved.read_bytes()
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"read failed: {exc}") from exc
    exec_ms = round((time.monotonic() - t0) * 1000)

    mime, _ = mimetypes.guess_type(resolved.name)

    logger.info(
        "read_file path=%s size=%s exec_ms=%s", resolved, len(content), exec_ms
    )

    return {
        "name": resolved.name,
        "path": str(resolved),
        "size": len(content),
        "mime": mime,
        "content_base64": base64.b64encode(content).decode("ascii"),
        "exec_ms": exec_ms,
    }


@app.post("/run")
async def run_command(req: RunRequest, authorization: str = Header()):
    _check_auth(authorization)

    # Allowlist check
    if req.command not in COMMAND_PATHS:
        raise HTTPException(
            status_code=403, detail=f"command not allowed: {req.command}"
        )

    # Validate stdin fields
    stdin_bytes: Optional[bytes] = None
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

    temp_dir: Optional[Path] = None
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

    # Run the command
    abs_path = COMMAND_PATHS[req.command]
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            abs_path,
            *injected_args,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout=COMMAND_TIMEOUT
        )
    except asyncio.TimeoutError:
        proc.kill()
        raise HTTPException(status_code=408, detail="command timed out")
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
        "command=%s exit_code=%s stdin_bytes=%s file_count=%s file_bytes=%s exec_ms=%s",
        req.command,
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
