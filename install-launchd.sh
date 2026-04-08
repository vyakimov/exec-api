#!/bin/sh
# Install exec-api as a macOS launchd service.
#
# Usage:
#   ./install-launchd.sh [--host HOST] [--port PORT] [--label LABEL]
#
# Required environment variable:
#   EXEC_API_TOKEN  — bearer token for authentication
#
# The script will:
#   1. Create a venv and install dependencies (if needed)
#   2. Generate a launchd plist from the template
#   3. Load the service
#
# Any additional environment variables you want the service to have
# can be added to the plist after installation.

set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="exec-api"
HOST="127.0.0.1"
PORT="8019"

while [ $# -gt 0 ]; do
    case "$1" in
        --host)  HOST="$2"; shift 2 ;;
        --port)  PORT="$2"; shift 2 ;;
        --label) LABEL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--host HOST] [--port PORT] [--label LABEL]"
            echo ""
            echo "  --host   Bind address (default: 127.0.0.1)"
            echo "  --port   Bind port (default: 8019)"
            echo "  --label  launchd service label (default: exec-api)"
            echo ""
            echo "Required: EXEC_API_TOKEN environment variable"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -z "${EXEC_API_TOKEN:-}" ]; then
    echo "error: EXEC_API_TOKEN must be set" >&2
    exit 1
fi

PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
UVICORN="$REPO_DIR/venv/bin/uvicorn"
LOG_DIR="$REPO_DIR/logs"

# Create venv if needed
if [ ! -x "$UVICORN" ]; then
    echo "Creating venv and installing dependencies..."
    if command -v uv >/dev/null 2>&1; then
        uv venv "$REPO_DIR/venv"
        uv pip install fastapi uvicorn --python "$REPO_DIR/venv/bin/python"
    else
        python3 -m venv "$REPO_DIR/venv"
        "$REPO_DIR/venv/bin/pip" install -q fastapi uvicorn
    fi
fi

# Create log directory
mkdir -p "$LOG_DIR"

# Unload existing service if present
if launchctl list "$LABEL" >/dev/null 2>&1; then
    echo "Unloading existing service..."
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
fi

# Generate plist
cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>EnvironmentVariables</key>
	<dict>
		<key>EXEC_API_TOKEN</key>
		<string>${EXEC_API_TOKEN}</string>
		<key>HOME</key>
		<string>${HOME}</string>
		<key>PATH</key>
		<string>${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>${LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>${UVICORN}</string>
		<string>server:app</string>
		<string>--host</string>
		<string>${HOST}</string>
		<string>--port</string>
		<string>${PORT}</string>
		<string>--log-level</string>
		<string>warning</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>${LOG_DIR}/exec-api.err.log</string>
	<key>StandardOutPath</key>
	<string>${LOG_DIR}/exec-api.log</string>
	<key>WorkingDirectory</key>
	<string>${REPO_DIR}</string>
</dict>
</plist>
PLIST

# Load the service
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"

echo "Installed and started: $LABEL"
echo "  Plist:  $PLIST_PATH"
echo "  Bind:   $HOST:$PORT"
echo "  Logs:   $LOG_DIR/"
echo ""
echo "To add more env vars (e.g. for commands that need API keys),"
echo "edit the plist and restart:"
echo "  launchctl kickstart -k gui/\$(id -u)/$LABEL"
