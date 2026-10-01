#!/usr/bin/env bash

fd0_test_isolation_error() {
    printf 'integration isolation: %s\n' "$*" >&2
    exit 1
}

fd0_test_require_isolation() {
    [ "${FD0_TEST_ISOLATED:-}" = "1" ] \
        || fd0_test_isolation_error "run through tests/run_isolated_integration.sh"
    [ -n "${FD0_TEST_ROOT:-}" ] && [ -d "$FD0_TEST_ROOT" ] \
        || fd0_test_isolation_error "FD0_TEST_ROOT is missing"
    [ -f "$FD0_TEST_ROOT/.fd0-test-isolated" ] \
        || fd0_test_isolation_error "isolation marker is missing"
    [ -n "${HOME:-}" ] && [ "$HOME" != "${FD0_TEST_REAL_HOME:-}" ] \
        || fd0_test_isolation_error "HOME is not isolated"
    case "$HOME/" in
        "$FD0_TEST_ROOT/"*) ;;
        *) fd0_test_isolation_error "HOME is outside FD0_TEST_ROOT" ;;
    esac
    case "${FD0_HOME:-$HOME/.fd0}/" in
        "$FD0_TEST_ROOT/"*) ;;
        *) fd0_test_isolation_error "FD0_HOME is outside FD0_TEST_ROOT" ;;
    esac
    case "${FD0_SSH_SOCK:-$FD0_TEST_ROOT/ssh.sock}" in
        "$FD0_TEST_ROOT"/*) ;;
        *) fd0_test_isolation_error "FD0_SSH_SOCK is outside FD0_TEST_ROOT" ;;
    esac
    case "${FD0_TEST_DEFAULT_SERVER:-}" in
        *.invalid) ;;
        *) fd0_test_isolation_error "test binaries must not fall back to the hosted server" ;;
    esac
    [ -n "${FD0_TEST_GO_LDFLAGS:-}" ] \
        || fd0_test_isolation_error "FD0_TEST_GO_LDFLAGS is missing"
}

fd0_test_stop_agents() {
    local pidfile pid
    while IFS= read -r pidfile; do
        [ -f "$pidfile" ] || continue
        pid=$(tr -d '[:space:]' < "$pidfile")
        case "$pid" in
            ''|*[!0-9]*) continue ;;
        esac
        if [ "$pid" != "$$" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done < <(find "$FD0_TEST_ROOT" -type f -name agent.pid 2>/dev/null)
}

fd0_test_stop_binary() {
    local binary=$1
    local match=${2:-}
    local pid command

    case "$binary" in
        "$FD0_TEST_ROOT"/*) ;;
        *) return 0 ;;
    esac
    [ -x "$binary" ] || return 0

    while IFS= read -r line; do
        pid=${line%% *}
        command=${line#* }
        case "$pid" in
            ''|*[!0-9]*) continue ;;
        esac
        case "$command" in
            "$binary"|"$binary "*)
                if [ -z "$match" ] || [[ "$command" =~ $match ]]; then
                    kill "$pid" 2>/dev/null || true
                fi
                ;;
        esac
    done < <(ps -axo pid=,command= | sed 's/^[[:space:]]*//')
}

# Restrict historical process-pattern cleanup to binaries and PID files owned by
# this isolated test root.
fd0_test_stop_matching() {
    local mode=${1:-}
    shift || true
    [ "$mode" = "-f" ] || return 0

    local pattern="$*"
    if [[ "$pattern" == *fd0-agent* ]]; then
        fd0_test_stop_agents
    fi
    if [[ "$pattern" == *fd0-server* ]]; then
        fd0_test_stop_binary "$HOME/go/bin/fd0-server" "$pattern"
    fi
    if [[ "$pattern" == *fd0-witness* ]]; then
        fd0_test_stop_binary "$HOME/go/bin/fd0-witness" "$pattern"
    fi
    if [[ "$pattern" == *fd0-test-mitm* ]]; then
        fd0_test_stop_binary "$HOME/go/bin/fd0-test-mitm" "$pattern"
    fi
    if [[ "$pattern" == *fd0-test-bad-witness* ]]; then
        fd0_test_stop_binary "$HOME/go/bin/fd0-test-bad-witness" "$pattern"
    fi
}
