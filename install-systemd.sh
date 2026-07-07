#!/bin/sh
# Install exec-api as a systemd user service (Linux counterpart of
# install-launchd.sh).
#
# Usage:
#   ./install-systemd.sh [--host HOST] [--port PORT] [--label LABEL] [--env-file PATH]
#
# The script will:
#   1. Create a venv and install dependencies (if needed)
#   2. Validate the .env file (default: .env in repo dir)
#   3. Generate a systemd user unit that loads it via EnvironmentFile
#   4. Enable and (re)start the service
#
# The .env file must contain EXEC_API_TOKEN at minimum. All other KEY=VALUE
# pairs are passed through to the service as environment variables (useful for
# API keys needed by allowlisted commands).
#
# .env format: one KEY=VALUE per line. Lines starting with # and blank lines
# are ignored. Values may be optionally quoted (systemd strips quotes itself).
#
# Note: the service runs in the user manager, so it stops at logout unless
# lingering is enabled: `loginctl enable-linger $USER`.

set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="exec-api"
HOST="127.0.0.1"
PORT="8019"
ENV_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --host)     HOST="$2"; shift 2 ;;
        --port)     PORT="$2"; shift 2 ;;
        --label)    LABEL="$2"; shift 2 ;;
        --env-file) ENV_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--host HOST] [--port PORT] [--label LABEL] [--env-file PATH]"
            echo ""
            echo "  --host      Bind address (default: 127.0.0.1)"
            echo "  --port      Bind port (default: 8019)"
            echo "  --label     systemd unit name (default: exec-api)"
            echo "  --env-file  Path to .env file (default: .env in repo directory)"
            echo ""
            echo "The .env file must contain EXEC_API_TOKEN at minimum."
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if ! command -v systemctl >/dev/null 2>&1; then
    echo "error: systemctl not found; on macOS use install-launchd.sh instead" >&2
    exit 1
fi

# Default env file location
if [ -z "$ENV_FILE" ]; then
    ENV_FILE="$REPO_DIR/.env"
fi

if [ ! -f "$ENV_FILE" ]; then
    echo "error: env file not found: $ENV_FILE" >&2
    echo "Create a .env file with at least EXEC_API_TOKEN=<token>" >&2
    exit 1
fi

if ! grep -q '^EXEC_API_TOKEN=' "$ENV_FILE"; then
    echo "error: EXEC_API_TOKEN not found in $ENV_FILE" >&2
    exit 1
fi

UNIT_DIR="$HOME/.config/systemd/user"
UNIT_PATH="$UNIT_DIR/${LABEL}.service"
UVICORN="$REPO_DIR/venv/bin/uvicorn"
LOG_DIR="$REPO_DIR/logs"

# Create venv if needed, then sync dependencies from requirements.txt. The
# requirements sync runs even when the venv already exists so a venv predating
# a new dependency is brought up to date rather than crash-looping on a
# missing import at startup.
REQUIREMENTS="$REPO_DIR/requirements.txt"
if command -v uv >/dev/null 2>&1; then
    [ -x "$UVICORN" ] || uv venv "$REPO_DIR/venv"
    uv pip install -r "$REQUIREMENTS" --python "$REPO_DIR/venv/bin/python"
else
    [ -x "$REPO_DIR/venv/bin/pip" ] || python3 -m venv "$REPO_DIR/venv"
    "$REPO_DIR/venv/bin/pip" install -q -r "$REQUIREMENTS"
fi

mkdir -p "$UNIT_DIR" "$LOG_DIR"

cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=exec-api — policy-checked filesystem ops and allowlisted commands over HTTP
After=network.target

[Service]
Type=exec
WorkingDirectory=${REPO_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${UVICORN} server:app --host ${HOST} --port ${PORT} --log-level warning
Restart=always
RestartSec=2
StandardOutput=append:${LOG_DIR}/exec-api.log
StandardError=append:${LOG_DIR}/exec-api.err.log

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable "$LABEL" >/dev/null 2>&1 || true
systemctl --user restart "$LABEL"

echo "Installed and started: $LABEL"
echo "  Unit:     $UNIT_PATH"
echo "  Env file: $ENV_FILE"
echo "  Bind:     $HOST:$PORT"
echo "  Logs:     $LOG_DIR/"
echo ""
echo "To update after changing .env:"
echo "  systemctl --user restart $LABEL"
echo "To survive logout:"
echo "  loginctl enable-linger \$USER"
