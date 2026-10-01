#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REAL_HOME=$HOME
RUN_ROOT=$(mktemp -d "/tmp/fd0-it.XXXXXX")
BUILD_BIN="$RUN_ROOT/bin"
PROD_AGENT_PID=
PROD_AGENT_SOCKET=
PROD_FD0_SHA=
PROD_AGENT_SHA=

snapshot_file() {
    local path=$1
    [ -e "$path" ] || return 0
    # GNU stat first: on Linux `stat -f` means file-system status and succeeds
    # with unrelated, changing output, which made this guard always fail.
    stat -c '%i:%Y:%s' "$path" 2>/dev/null || stat -f '%i:%m:%z' "$path"
}

snapshot_binary() {
    local path=$1
    [ -f "$path" ] || return 0
    shasum -a 256 "$path" | awk '{print $1}'
}

PROD_FD0_BIN=$(command -v fd0 2>/dev/null || true)
PROD_AGENT_BIN=$(command -v fd0-agent 2>/dev/null || true)
PROD_FD0_SHA=$(snapshot_binary "$PROD_FD0_BIN")
PROD_AGENT_SHA=$(snapshot_binary "$PROD_AGENT_BIN")
PROD_AGENT_SOCKET=$(snapshot_file "$REAL_HOME/.fd0/agent.sock")
if [ -f "$REAL_HOME/.fd0/agent.pid" ]; then
    PROD_AGENT_PID=$(tr -d '[:space:]' < "$REAL_HOME/.fd0/agent.pid")
fi

verify_production_unchanged() {
    local failed=0
    [ "$(snapshot_binary "$PROD_FD0_BIN")" = "$PROD_FD0_SHA" ] || failed=1
    [ "$(snapshot_binary "$PROD_AGENT_BIN")" = "$PROD_AGENT_SHA" ] || failed=1
    [ "$(snapshot_file "$REAL_HOME/.fd0/agent.sock")" = "$PROD_AGENT_SOCKET" ] || failed=1
    if [ -n "$PROD_AGENT_PID" ]; then
        [ -f "$REAL_HOME/.fd0/agent.pid" ] || failed=1
        [ "$(tr -d '[:space:]' < "$REAL_HOME/.fd0/agent.pid")" = "$PROD_AGENT_PID" ] || failed=1
        kill -0 "$PROD_AGENT_PID" 2>/dev/null || failed=1
    fi
    [ "$failed" -eq 0 ] \
        || { printf 'integration isolation: production fd0 state changed\n' >&2; return 1; }
}

# Scripts start agents and servers from this run's binaries; some leave them
# running. Stop every process whose executable lives under RUN_ROOT and only
# those, so nothing outside the test run is touched.
stop_run_processes() {
    pkill -f "^$RUN_ROOT/" 2>/dev/null || true
}

cleanup() {
    local code=$?
    stop_run_processes
    verify_production_unchanged || code=1
    if [ "$code" -eq 0 ]; then
        rm -rf "$RUN_ROOT"
    else
        printf 'integration isolation: preserved failed run at %s\n' "$RUN_ROOT" >&2
    fi
    exit "$code"
}
trap cleanup EXIT INT TERM

# Test binaries must never reach the hosted production server. The client
# falls back to fdhome.DefaultServer when no server is configured, so every
# test build replaces it with an unresolvable .invalid host (RFC 2606).
TEST_DEFAULT_SERVER="http://default-server.fd0-test.invalid"
TEST_GO_LDFLAGS="-X $(cd "$ROOT" && go list ./internal/fdhome).DefaultServer=$TEST_DEFAULT_SERVER"

mkdir -p "$BUILD_BIN"
for spec in \
    "fd0:./cmd/fd0" \
    "fd0-agent:./cmd/fd0-agent" \
    "fd0-desktop-bridge:./cmd/fd0-desktop-bridge" \
    "fd0-server:./cmd/fd0-server" \
    "fd0-witness:./cmd/fd0-witness" \
    "fd0-test-mitm:./cmd/fd0-test-mitm" \
    "fd0-test-bad-witness:./cmd/fd0-test-bad-witness" \
    "fd0-test-drop-scope-event:./tests/helpers/drop_scope_event" \
    "fd0-test-tamper-scope-link:./tests/helpers/tamper_scope_link" \
    "fd0-test-compact-scope-chain:./tests/helpers/compact_scope_chain"; do
    name=${spec%%:*}
    package=${spec#*:}
    go build -ldflags "$TEST_GO_LDFLAGS" -o "$BUILD_BIN/$name" "$package"
done
for name in fd0 fd0-agent fd0-desktop-bridge; do
    grep -aqF "$TEST_DEFAULT_SERVER" "$BUILD_BIN/$name" \
        || { printf 'integration isolation: %s does not carry the test default server\n' "$name" >&2; exit 1; }
done

if [ "$#" -eq 0 ]; then
    set -- "$ROOT"/tests/integration_*.sh
fi

for script in "$@"; do
    case "$script" in
        /*) ;;
        *) script="$ROOT/$script" ;;
    esac
    [ -f "$script" ] || { printf 'missing integration test: %s\n' "$script" >&2; exit 1; }

    name=$(basename "$script" .sh)
    case_root="$RUN_ROOT/cases/$name"
    test_home="$case_root/home"
    test_bin="$test_home/go/bin"
    test_tmp="$case_root/tmp"
    mkdir -p "$test_bin" "$test_tmp"
    : > "$case_root/.fd0-test-isolated"
    for binary in "$BUILD_BIN"/*; do
        ln -s "$binary" "$test_bin/$(basename "$binary")"
    done

    printf '=== %s ===\n' "$script"
    env \
        HOME="$test_home" \
        TMPDIR="$test_tmp" \
        XDG_CONFIG_HOME="$test_home/.config" \
        XDG_DATA_HOME="$test_home/.local/share" \
        XDG_CACHE_HOME="$test_home/.cache" \
        GNUPGHOME="$test_home/.gnupg" \
        KUBECONFIG="$test_home/.kube/config" \
        TALOSCONFIG="$test_home/.talos/config" \
        FD0_TEST_ISOLATED=1 \
        FD0_TEST_ROOT="$case_root" \
        FD0_TEST_REAL_HOME="$REAL_HOME" \
        FD0_HOME="$test_home/.fd0" \
        FD0_SSH_SOCK="$case_root/fd0-ssh.sock" \
        FD0_SERVER= \
        FD0_TEST_DEFAULT_SERVER="$TEST_DEFAULT_SERVER" \
        FD0_TEST_GO_LDFLAGS="$TEST_GO_LDFLAGS" \
        FD0_AGENT_BIN="$test_bin/fd0-agent" \
        FD0="$test_bin/fd0" \
        FD0_AGENT="$test_bin/fd0-agent" \
        FD0_WITNESS="$test_bin/fd0-witness" \
        FD0_MITM="$test_bin/fd0-test-mitm" \
        FD0_BAD_WITNESS="$test_bin/fd0-test-bad-witness" \
        PATH="$test_bin:$PATH" \
        bash "$script" || script_status=$?
    stop_run_processes
    [ "${script_status:-0}" -eq 0 ] || exit "$script_status"
done
