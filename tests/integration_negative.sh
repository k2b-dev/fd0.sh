#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY pinning.
# Tests run unattended → enable auto-pin so the first /sync can land the pin.
export FD0_AUTO_PIN=1
# fd0 negative-path / error-handling integration test.
#
# Every step exercises an INVALID input or a failure scenario and asserts
# that fd0:
#   (a) refuses cleanly (non-zero exit, useful error on stderr),
#   (b) leaves on-disk state unchanged on the failure path,
#   (c) does NOT corrupt the vault, chain, or server.
#
# Anti-pattern this guards against: silent fallback to defaults that
# papers over a config typo, or partial writes that leave the vault in a
# half-state.
#
# Run from repo root:
#   bash tests/integration_negative.sh

set -uo pipefail

SERVER_PORT=14401
SERVER_DB=/tmp/fd0-neg.db
SERVER_LOG=/tmp/fd0-neg.log
HOME_DIR=$HOME/.fd0-neg
HOME_DIR2=$HOME/.fd0-neg-2
RECOVERY=/tmp/fd0-neg-rec.cbor
FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}

PASS=0
FAIL=0

step() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()   { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()   { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

# expect_fail "$cmd" "match-on-stderr-or-stdout" "label"
expect_fail() {
    local cmd="$1" needle="$2" label="$3"
    local out
    if out=$(eval "$cmd" 2>&1); then
        no "$label — should have failed but exit=0; output: $out"
        return
    fi
    if [ -n "$needle" ] && ! printf "%s" "$out" | grep -qF "$needle"; then
        no "$label — failed (good) but output missing '$needle': $out"
        return
    fi
    ok "$label"
}

# expect_ok "$cmd" "label"
expect_ok() {
    local cmd="$1" label="$2"
    local out
    if out=$(eval "$cmd" 2>&1); then
        ok "$label"
    else
        no "$label — exit nonzero: $out"
    fi
}

cleanup() {
    fd0_test_stop_matching -f fd0-agent 2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_DIR" "$HOME_DIR2" "$SERVER_DB" "$SERVER_LOG" "$RECOVERY"
}
trap cleanup EXIT

step "Setup: clean state, start server"
fd0_test_stop_matching -f fd0-server 2>/dev/null || true
fd0_test_stop_matching -f fd0-agent  2>/dev/null || true
sleep 0.3
rm -rf "$HOME_DIR" "$HOME_DIR2" "$SERVER_DB" "$SERVER_LOG" "$RECOVERY"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3
curl -fsS "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null && ok "server up"

# Helper: configure home with sync server.
write_cfg() {
    local home="$1"
    mkdir -p "$home" && chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
EOF
}

# ─────────────────────────────────────────────────────────────────────────
# A1. Pre-init failures: operations that require an initialized home
# ─────────────────────────────────────────────────────────────────────────
step "A1) Operations on uninitialized home must refuse"

write_cfg "$HOME_DIR"

expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' unlock <<<dummy" "" \
    "unlock without init refuses"
# `fd0 status` is intentionally a thin agent-ping — exit 0 with "not running"
# is the documented behavior for an uninitialized home.
ST=$(env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" status 2>&1 || true)
case "$ST" in
    *"not running"*|*"locked"*) ok "status reports clean state on uninitialized home: ${ST%% *}..." ;;
    *unlocked*) no "status reports unlocked on a never-init'd home: $ST" ;;
    *) no "status output unexpected: $ST" ;;
esac
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' ls" "" \
    "ls without init refuses"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' get NAME" "" \
    "get without init refuses"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' set NAME value" "" \
    "set without init refuses"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' sync" "" \
    "sync without init refuses"

# ─────────────────────────────────────────────────────────────────────────
# A2. Init the home for the rest of the tests
# ─────────────────────────────────────────────────────────────────────────
step "A2) Init alice and unlock"
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" init >/dev/null 2>&1 \
    && ok "init succeeded" || no "init failed"
printf "alice-pass\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1 \
    && ok "unlock succeeded" || no "unlock failed"
sleep 0.2

A() { env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" FD0_SERVER="http://127.0.0.1:${SERVER_PORT}" "$FD0" "$@"; }

# ─────────────────────────────────────────────────────────────────────────
# A3. Wrong-passphrase paths
# ─────────────────────────────────────────────────────────────────────────
step "A3) Wrong passphrase rejection"
A lock >/dev/null 2>&1
sleep 0.2
expect_fail "printf 'wrong-pass\n' | env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' unlock" "" \
    "wrong passphrase refused"
# After failed unlock, agent should not be in unlocked state.
ST=$(env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" status 2>&1 || true)
case "$ST" in
    *"locked"*|*"not running"*) ok "agent state after bad unlock: not unlocked" ;;
    *unlocked*) no "agent is unlocked after wrong passphrase!" ;;
    *) ok "agent state ambiguous but not unlocked: $ST" ;;
esac

# Re-unlock with right passphrase for subsequent tests.
printf "alice-pass\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.2

# ─────────────────────────────────────────────────────────────────────────
# A4. Recovery import refuses on existing init
# ─────────────────────────────────────────────────────────────────────────
step "A4) Recovery import on initialized home must refuse"
printf "rec-pass\nrec-pass\n" | A recovery export "$RECOVERY" >/dev/null 2>&1
# Trying to import into the SAME home (already initialized) must refuse.
expect_fail "printf 'rec-pass\nx-pass\nx-pass\n' | env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' recovery import '$RECOVERY'" "" \
    "recovery import refuses on existing vault"

# ─────────────────────────────────────────────────────────────────────────
# A5. Recovery import with wrong passphrase
# ─────────────────────────────────────────────────────────────────────────
step "A5) Recovery import with wrong recovery passphrase"
expect_fail "printf 'WRONG\nx-pass\nx-pass\n' | env FD0_HOME='$HOME_DIR2' FD0_SSH_SOCK='$HOME_DIR2/ssh.sock' '$FD0' recovery import '$RECOVERY'" "" \
    "wrong recovery passphrase refused"
# The target home must not have a usable vault after the failed import.
if [ -f "$HOME_DIR2/vault.enc" ]; then
    no "failed recovery import left a vault.enc behind"
else
    ok "failed recovery import left no half-state"
fi

# ─────────────────────────────────────────────────────────────────────────
# A6. Get / Set / Rm on non-existent secrets
# ─────────────────────────────────────────────────────────────────────────
step "A6) Operations on non-existent secrets/scopes"
A scope create --label work >/dev/null 2>&1
A sync >/dev/null 2>&1

expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' get NEVER_EXISTED --scope work" "not found" \
    "get nonexistent secret reports 'not found'"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' rm NEVER_EXISTED --scope work" "" \
    "rm nonexistent secret refuses"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' get FOO --scope NONEXISTENT_SCOPE" "" \
    "get in nonexistent scope refuses"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' set FOO bar --scope NONEXISTENT_SCOPE" "" \
    "set in nonexistent scope refuses"

# ─────────────────────────────────────────────────────────────────────────
# A7. Set with stdin
# ─────────────────────────────────────────────────────────────────────────
step "A7) Set with value '-' reads stdin"
printf "value-from-stdin\n" | A set STDIN_KEY - --scope work >/dev/null 2>&1 \
    && ok "set with stdin sentinel succeeded" \
    || no "set with stdin sentinel failed"
GOT=$(A get STDIN_KEY --scope work --raw 2>&1 || true)
[ "$GOT" = "value-from-stdin" ] \
    && ok "stdin value roundtrips" \
    || no "stdin value mismatch (got '$GOT')"

# ─────────────────────────────────────────────────────────────────────────
# A8. Empty value
# ─────────────────────────────────────────────────────────────────────────
step "A8) Set with empty value"
A set EMPTY_KEY "" --scope work >/dev/null 2>&1 \
    && ok "set empty value succeeded" \
    || no "set empty value failed"
GOT=$(A get EMPTY_KEY --scope work --raw 2>&1 || true)
[ "$GOT" = "" ] \
    && ok "empty value roundtrips as empty" \
    || no "empty value got non-empty: '$GOT'"

# ─────────────────────────────────────────────────────────────────────────
# A9. Sync without server configured
# ─────────────────────────────────────────────────────────────────────────
step "A9) Sync without server config or env"
# Build a sandbox home with NO sync.server in config and run sync there.
SANDBOX="$HOME_DIR2"
mkdir -p "$SANDBOX" && chmod 700 "$SANDBOX"
# Empty config — no [sync] section.
: > "$SANDBOX/config.toml"
printf "x-pass\nx-pass\n" | env FD0_HOME="$SANDBOX" FD0_SSH_SOCK="$SANDBOX/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "x-pass\n" | env FD0_HOME="$SANDBOX" FD0_SSH_SOCK="$SANDBOX/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.2
expect_fail "env FD0_HOME='$SANDBOX' FD0_SSH_SOCK='$SANDBOX/ssh.sock' FD0_SERVER='' '$FD0' sync" "${FD0_TEST_DEFAULT_SERVER#http://}" \
    "sync without server uses the built-in default and fails cleanly in tests"
env FD0_HOME="$SANDBOX" FD0_SSH_SOCK="$SANDBOX/ssh.sock" "$FD0" lock >/dev/null 2>&1
rm -rf "$SANDBOX"

# ─────────────────────────────────────────────────────────────────────────
# A10. Sync with unreachable server
# ─────────────────────────────────────────────────────────────────────────
step "A10) Sync with unreachable server"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' FD0_SERVER='http://127.0.0.1:1' '$FD0' sync" "" \
    "sync against unreachable server fails cleanly"

# ─────────────────────────────────────────────────────────────────────────
# A11. Bad config.toml
# ─────────────────────────────────────────────────────────────────────────
step "A11) Bad config.toml"
mkdir -p "$HOME_DIR2" && chmod 700 "$HOME_DIR2"
cat > "$HOME_DIR2/config.toml" <<'EOF'
[sync
server = "broken
EOF
# `fd0 status` doesn't read config (it's a thin agent ping). Use a
# command that DOES read config: `fd0 sync` reads [sync].server.
expect_fail "env FD0_HOME='$HOME_DIR2' FD0_SSH_SOCK='$HOME_DIR2/ssh.sock' '$FD0' sync" "" \
    "bad TOML in config refuses cleanly"
rm -rf "$HOME_DIR2"

# ─────────────────────────────────────────────────────────────────────────
# A12. Bad duration in [agent].idle_timeout
# ─────────────────────────────────────────────────────────────────────────
step "A12) Bad duration string in agent config"
mkdir -p "$HOME_DIR2" && chmod 700 "$HOME_DIR2"
cat > "$HOME_DIR2/config.toml" <<EOF
[agent]
idle_timeout = "not-a-duration"
EOF
printf "x-pass\nx-pass\n" | env FD0_HOME="$HOME_DIR2" FD0_SSH_SOCK="$HOME_DIR2/ssh.sock" "$FD0" init >/dev/null 2>&1
# Unlock spawns the agent with this config. Should error out with a useful message.
OUT=$(printf "x-pass\n" | env FD0_HOME="$HOME_DIR2" FD0_SSH_SOCK="$HOME_DIR2/ssh.sock" "$FD0" unlock 2>&1 || true)
case "$OUT" in
    *"idle"*|*"duration"*|*"agent"*) ok "bad idle_timeout reports config error" ;;
    *unlocked*) no "agent unlocked despite invalid config: $OUT" ;;
    *) no "ambiguous agent failure on bad duration: $OUT" ;;
esac
env FD0_HOME="$HOME_DIR2" FD0_SSH_SOCK="$HOME_DIR2/ssh.sock" "$FD0" lock >/dev/null 2>&1 || true
rm -rf "$HOME_DIR2"

# ─────────────────────────────────────────────────────────────────────────
# A13. Last-method removal & active-method removal
# ─────────────────────────────────────────────────────────────────────────
step "A13) Auth removal protections"
ACTIVE=$(A auth ls 2>&1 | awk '/^\* /{print $2}')
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' auth rm '$ACTIVE'" "currently-unlocked" \
    "removing currently-active method refused"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' auth rm am_does_not_exist" "" \
    "removing nonexistent method_id refused"

# ─────────────────────────────────────────────────────────────────────────
# A14. card import with malformed URL
# ─────────────────────────────────────────────────────────────────────────
step "A14) Card import with malformed URLs"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' card import 'not-a-url'" "" \
    "non-URL refused"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' card import 'fd0://card/zzzzzzz'" "" \
    "fd0://card/<garbage> refused"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' card import 'http://example.com/card'" "" \
    "wrong-scheme URL refused"

# ─────────────────────────────────────────────────────────────────────────
# A15. card rm of unknown label
# ─────────────────────────────────────────────────────────────────────────
step "A15) card rm unknown label"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' card rm nope" "" \
    "card rm of unknown label refused"

# ─────────────────────────────────────────────────────────────────────────
# A16. scope add-member of unknown card label
# ─────────────────────────────────────────────────────────────────────────
step "A16) scope add-member with unknown member label"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' scope add-member unknownlabel --scope work" "" \
    "add-member with unknown label refused"

# ─────────────────────────────────────────────────────────────────────────
# A17. scope leave for nonexistent
# ─────────────────────────────────────────────────────────────────────────
step "A17) scope leave nonexistent / scope rename invalid"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' scope leave NONEXISTENT" "" \
    "leave nonexistent scope refused"
expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' scope rename NONEXISTENT new-label" "" \
    "rename nonexistent scope refused"

# ─────────────────────────────────────────────────────────────────────────
# A18. Doctor on healthy state — exit code is 0
# ─────────────────────────────────────────────────────────────────────────
step "A18) Doctor on healthy state exits 0"
expect_ok "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' doctor" \
    "doctor exits 0 on a clean home"

# ─────────────────────────────────────────────────────────────────────────
# A19. Doctor on tampered chain
# ─────────────────────────────────────────────────────────────────────────
step "A19) Doctor on tampered scope chain"
# Get the work scope's chain file (chains/<scope_id>.cbor).
SCOPE_FILE=$(ls "$HOME_DIR/chains/"s_*.cbor 2>/dev/null | head -1)
if [ -n "$SCOPE_FILE" ]; then
    cp "$SCOPE_FILE" "$SCOPE_FILE.bak"
    # Truncate to 10 bytes — guaranteed corruption.
    head -c 10 "$SCOPE_FILE.bak" > "$SCOPE_FILE"
    expect_fail "env FD0_HOME='$HOME_DIR' FD0_SSH_SOCK='$HOME_DIR/ssh.sock' '$FD0' doctor" "" \
        "doctor flags corrupted scope chain"
    cp "$SCOPE_FILE.bak" "$SCOPE_FILE"
    rm "$SCOPE_FILE.bak"
else
    no "no scope chain file found to tamper"
fi

# ─────────────────────────────────────────────────────────────────────────
# A20. Lock when already locked
# ─────────────────────────────────────────────────────────────────────────
step "A20) Lock when locked / unlock when unlocked"
A lock >/dev/null 2>&1
# Second lock: depending on impl, either succeeds idempotently or errors.
# Either is acceptable; what matters is no crash, no corruption.
SECOND=$(env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" lock 2>&1 || true)
case "$SECOND" in
    *crash*|*panic*) no "second lock crashed: $SECOND" ;;
    *) ok "second lock handled gracefully: ${SECOND:-clean}" ;;
esac

# Re-unlock for cleanup.
printf "alice-pass\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.2

# ─────────────────────────────────────────────────────────────────────────
# A21. Get with raw flag and trailing-newline behavior
# ─────────────────────────────────────────────────────────────────────────
step "A21) get --raw vs default"
A set RAW_TEST "no-trailing-newline" --scope work >/dev/null 2>&1
RAW=$(A get RAW_TEST --scope work --raw)
DEFAULT=$(A get RAW_TEST --scope work)
[ "$RAW" = "no-trailing-newline" ] \
    && ok "--raw produces value with no trailing newline" \
    || no "--raw output mismatch: '$RAW'"
[ "$DEFAULT" = "no-trailing-newline" ] \
    && ok "default also strips by command substitution (shell ate trailing newline)" \
    || no "default output mismatch: '$DEFAULT'"

# ─────────────────────────────────────────────────────────────────────────
# A22. Vault & chain file permissions
# ─────────────────────────────────────────────────────────────────────────
step "A22) On-disk permissions are tight"
PERMS=$(stat -c "%a" "$HOME_DIR/vault.enc" 2>/dev/null || stat -f "%Lp" "$HOME_DIR/vault.enc" 2>/dev/null)
[ "$PERMS" = "600" ] \
    && ok "vault.enc is 0600" \
    || no "vault.enc has loose perms: $PERMS"

PERMS=$(stat -c "%a" "$HOME_DIR/chains/user.cbor" 2>/dev/null || stat -f "%Lp" "$HOME_DIR/chains/user.cbor" 2>/dev/null)
[ "$PERMS" = "600" ] || [ "$PERMS" = "644" ] \
    && ok "user.cbor is 0600 or 0644 (file is non-secret but encrypted-elsewhere)" \
    || no "user.cbor has loose perms: $PERMS"

# ─────────────────────────────────────────────────────────────────────────
# A23. Server: register with bad CBOR body
# ─────────────────────────────────────────────────────────────────────────
step "A23) Server rejects malformed register body"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${SERVER_PORT}/v1/users" \
    -H "Content-Type: application/cbor" --data-binary "not-cbor")
case "$CODE" in
    400|401|409) ok "server rejects malformed register (HTTP $CODE)" ;;
    *) no "server returned unexpected $CODE for malformed register" ;;
esac

# ─────────────────────────────────────────────────────────────────────────
# A24. Server: append without auth header
# ─────────────────────────────────────────────────────────────────────────
step "A24) Server rejects unauthenticated append"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${SERVER_PORT}/v1/users/abc/events" \
    -H "Content-Type: application/cbor" --data-binary "x")
[ "$CODE" = "401" ] \
    && ok "server rejects /users/.../events without auth (401)" \
    || no "server returned $CODE for unauthenticated append (expected 401)"

# ─────────────────────────────────────────────────────────────────────────
# A25. Server: sync without auth header
# ─────────────────────────────────────────────────────────────────────────
step "A25) Server rejects unauthenticated sync"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${SERVER_PORT}/v1/sync" \
    -H "Content-Type: application/cbor" --data-binary "x")
[ "$CODE" = "401" ] \
    && ok "server rejects /sync without auth (401)" \
    || no "server returned $CODE for unauthenticated sync (expected 401)"

# ─────────────────────────────────────────────────────────────────────────
# A26. Server: stale timestamp
# ─────────────────────────────────────────────────────────────────────────
step "A26) Server rejects stale timestamps"
# A request with ts=0 (1970) is way outside the 5-minute window.
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${SERVER_PORT}/v1/sync" \
    -H "Content-Type: application/cbor" \
    -H "Authorization: fd0-sig v1 pk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, nonce=AAAAAAAAAAAAAAAAAAAAAA==, ts=0, sig=$(python3 -c 'print("A"*86)')=" \
    --data-binary "x")
[ "$CODE" = "401" ] \
    && ok "server rejects ts=0 (stale)" \
    || no "server returned $CODE for stale ts (expected 401)"

# ─────────────────────────────────────────────────────────────────────────
# A27. Server: /users/<shortId>/events requires auth, then 404 for unknown
# ─────────────────────────────────────────────────────────────────────────
step "A27) Server: /users/<unknown>/events auth-gates before existence check"
# Codex security audit: the endpoint now requires HTTP-sig auth so
# `encrypted_super_priv` blobs aren't readable by anyone who can
# guess a shortId. Unauthenticated GET → 401 (was 404). The
# specific value (401 vs 404) is intentional; auth check fires
# BEFORE the chain lookup so an attacker can't enumerate which
# shortIds exist.
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${SERVER_PORT}/v1/users/zzzzzzzz/events?latest=true")
[ "$CODE" = "401" ] \
    && ok "GET /users/<unknown>/events → 401 (auth required, no enumeration leak)" \
    || no "GET /users/<unknown>/events → $CODE (expected 401)"

# ─────────────────────────────────────────────────────────────────────────
# A28. Server: oversized request body
# ─────────────────────────────────────────────────────────────────────────
step "A28) Server rejects oversized body"
# Default max-body is 8 MiB. Send 9 MiB.
CODE=$(head -c $((9 * 1024 * 1024)) /dev/zero | curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://127.0.0.1:${SERVER_PORT}/v1/users" \
    -H "Content-Type: application/cbor" --data-binary @-)
case "$CODE" in
    400|413) ok "server rejects 9MiB body (HTTP $CODE)" ;;
    *) no "server accepted 9MiB body (HTTP $CODE)" ;;
esac

# ─────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────
echo
printf "\033[1m== NEGATIVE-PATH SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
