#!/bin/sh
# Install exec-api as a macOS launchd service.
#
# Usage:
#   ./install-launchd.sh [--host HOST] [--port PORT] [--label LABEL] [--env-file PATH]
#
# The script will:
#   1. Create a venv and install dependencies (if needed)
#   2. Read environment variables from a .env file (default: .env in repo dir)
#   3. Generate a launchd plist with those variables
#   4. Load the service
#
# The .env file must contain EXEC_API_TOKEN at minimum. All other
# KEY=VALUE pairs are passed through to the service as environment
# variables (useful for API keys needed by allowlisted commands).
#
# .env format: one KEY=VALUE per line. Lines starting with # and
# blank lines are ignored. Values may be optionally quoted.

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
            echo "  --label     launchd service label (default: exec-api)"
            echo "  --env-file  Path to .env file (default: .env in repo directory)"
            echo ""
            echo "The .env file must contain EXEC_API_TOKEN at minimum."
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Default env file location
if [ -z "$ENV_FILE" ]; then
    ENV_FILE="$REPO_DIR/.env"
fi

if [ ! -f "$ENV_FILE" ]; then
    echo "error: env file not found: $ENV_FILE" >&2
    echo "Create a .env file with at least EXEC_API_TOKEN=<token>" >&2
    exit 1
fi

# Parse .env file into plist XML fragments and validate EXEC_API_TOKEN
ENV_XML=""
HAS_TOKEN=false

while IFS= read -r line || [ -n "$line" ]; do
    # Skip blank lines and comments
    case "$line" in
        ""|\#*) continue ;;
    esac

    key="${line%%=*}"
    value="${line#*=}"

    # Strip optional quotes from value
    case "$value" in
        \"*\") value="${value#\"}"; value="${value%\"}" ;;
        \'*\') value="${value#\'}"; value="${value%\'}" ;;
    esac

    # Escape XML special characters in value
    value=$(printf '%s' "$value" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

    ENV_XML="${ENV_XML}		<key>${key}</key>
		<string>${value}</string>
"
    if [ "$key" = "EXEC_API_TOKEN" ]; then
        HAS_TOKEN=true
    fi
done < "$ENV_FILE"

if [ "$HAS_TOKEN" = false ]; then
    echo "error: EXEC_API_TOKEN not found in $ENV_FILE" >&2
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
    # bootout is async; bootstrap racing teardown returns errno 5 ("Input/output error").
    # Poll until the service is fully gone (max ~5s).
    i=0
    while launchctl list "$LABEL" >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge 10 ]; then
            echo "warning: service still present after 5s; continuing" >&2
            break
        fi
        sleep 0.5
    done
fi

# Generate plist
cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>EnvironmentVariables</key>
	<dict>
${ENV_XML}		<key>HOME</key>
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
echo "  Plist:    $PLIST_PATH"
echo "  Env file: $ENV_FILE"
echo "  Bind:     $HOST:$PORT"
echo "  Logs:     $LOG_DIR/"
echo ""
echo "To update after changing .env, re-run this script or:"
echo "  launchctl kickstart -k gui/\$(id -u)/$LABEL"
