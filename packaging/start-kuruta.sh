#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
data_dir=${XDG_DATA_HOME:-"$HOME/.local/share"}/kuruta
mkdir -p "$data_dir"

server="$script_dir/kuruta-server"
agent="$script_dir/kuruta-agent"
if [ ! -x "$server" ] || [ ! -x "$agent" ]; then
    printf '%s\n' "Extract the complete Kuruta release archive and keep both binaries beside this script." >&2
    exit 1
fi

export KURUTA_DB_PATH="$data_dir/kuruta.db"
"$server" >"$data_dir/server.log" 2>&1 &
server_pid=$!
agent_pid=

cleanup() {
    if [ -n "$agent_pid" ]; then
        kill "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

"$agent" >"$data_dir/agent.log" 2>"$data_dir/agent-error.log" &
agent_pid=$!
printf '%s\n' "Kuruta is running. Open http://127.0.0.1:8765/docs"
printf 'Logs and database: %s\nPress Ctrl+C to stop Kuruta.\n' "$data_dir"

while kill -0 "$server_pid" 2>/dev/null && kill -0 "$agent_pid" 2>/dev/null; do
    sleep 1
done

if ! kill -0 "$server_pid" 2>/dev/null; then
    printf '%s\n' "Kuruta server exited. Check $data_dir/server.log" >&2
    exit 1
fi
printf '%s\n' "Kuruta agent exited. Check $data_dir/agent-error.log" >&2
exit 1
