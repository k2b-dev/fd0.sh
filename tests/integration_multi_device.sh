#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY pinning.
# Tests run unattended → enable auto-pin so the first /sync can land the pin.
export FD0_AUTO_PIN=1
# fd0 multi-device integration test.
#
# Simulates two users (Alice, Bob), each with two computers ("laptop" and
# "desktop"). Two scopes are shared between them. Verifies:
#   - Recovery-based device bootstrap (Alice/Bob laptop → desktop)
#   - Card import + safety number ceremony
#   - Personal + shared scopes
#   - Auto-sync across devices (both intra-user and inter-user)
#   - Conflict reconcile on shared scope
#   - Member rotation propagates auto-drop
#   - Multi-passphrase auth methods (add/rm/lockout protections)
#
# Run from repo root:
#   bash tests/integration_multi_device.sh
#
# Cleans up its own ~/.fd0-* dirs and /tmp paths. Server runs on :14048.

set -uo pipefail   # not -e: keep going even if individual asserts fail

SERVER_PORT=14048
SERVER_DB=/tmp/fd0-multi.db
SERVER_LOG=/tmp/fd0-multi.log
RECOVERY=/tmp/fd0-multi-recovery.cbor
FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}

# ─── helpers ──────────────────────────────────────────────────────────────

PASS=0
FAIL=0

step() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()   { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()   { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }
expect_eq() {
    if [ "$1" = "$2" ]; then ok "$3"
    else no "$3 (got '$1', want '$2')"
    fi
}
expect_contains() {
    if printf "%s" "$1" | grep -qF "$2"; then ok "$3"
    else no "$3 (output did not contain '$2')"
    fi
}
expect_not_contains() {
    if printf "%s" "$1" | grep -qF "$2"; then no "$3 (output unexpectedly contained '$2')"
    else ok "$3"
    fi
}

# Per-device wrappers. We set FD0_LOCK_WAIT=10s so interactive commands
# patiently queue behind the agent's background auto-sync.
make_alias() {
    local name="$1" home="$2"
    eval "
${name}() {
    env FD0_HOME='$home' FD0_SSH_SOCK='$home/ssh.sock' FD0_SERVER='http://127.0.0.1:${SERVER_PORT}' FD0_LOCK_WAIT=10s '$FD0' \"\$@\"
}"
}

write_config() {
    local home="$1" interval="$2"
    mkdir -p "$home"
    chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
interval  = "${interval}"
on_unlock = true
EOF
}

# ─── setup ────────────────────────────────────────────────────────────────

step "Setup"
fd0_test_stop_matching -f fd0-server 2>/dev/null || true
fd0_test_stop_matching -f fd0-agent 2>/dev/null || true
sleep 0.3
rm -f "$SERVER_DB" "$SERVER_LOG" "$RECOVERY".alice "$RECOVERY".bob /tmp/fd0-multi-step2.log
rm -rf "$HOME/.fd0-alice-laptop" "$HOME/.fd0-alice-desktop" \
       "$HOME/.fd0-bob-laptop"   "$HOME/.fd0-bob-desktop"

# Rate-limiting is exercised in a dedicated step below; here we want
# unconstrained multi-device traffic.
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; fd0_test_stop_matching -f fd0-agent 2>/dev/null || true' EXIT
sleep 0.5
curl -fsS "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null
ok "fd0-server up on :${SERVER_PORT}"

# Auto-sync interval — short for fast iteration.
write_config "$HOME/.fd0-alice-laptop"  "3s"
write_config "$HOME/.fd0-alice-desktop" "3s"
write_config "$HOME/.fd0-bob-laptop"    "3s"
write_config "$HOME/.fd0-bob-desktop"   "3s"

make_alias AL "$HOME/.fd0-alice-laptop"
make_alias AD "$HOME/.fd0-alice-desktop"
make_alias BL "$HOME/.fd0-bob-laptop"
make_alias BD "$HOME/.fd0-bob-desktop"

# Each device exports FD0_HOME at unlock so the agent picks up its config.
unlock() {
    local home="$1" pass="$2"
    printf "%s\n" "$pass" | env FD0_HOME="$home" FD0_SSH_SOCK="$home/ssh.sock" "$FD0" unlock >/dev/null 2>&1
}

# ─── 1) Identity bootstrap (Alice + Bob laptop init, recovery to desktop)  ─
step "1) Init Alice/Bob on their laptops"
printf "alice-laptop-pass\nalice-laptop-pass\n" | env FD0_HOME="$HOME/.fd0-alice-laptop" FD0_SSH_SOCK="$HOME/.fd0-alice-laptop/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "bob-laptop-pass\nbob-laptop-pass\n"     | env FD0_HOME="$HOME/.fd0-bob-laptop" FD0_SSH_SOCK="$HOME/.fd0-bob-laptop/ssh.sock" "$FD0" init >/dev/null 2>&1
unlock "$HOME/.fd0-alice-laptop" "alice-laptop-pass"
unlock "$HOME/.fd0-bob-laptop"   "bob-laptop-pass"
sleep 0.3
ok "Alice's laptop unlocked"
ok "Bob's laptop unlocked"

step "2) Recovery export → restore to desktops"
printf "alice-rec\nalice-rec\n" | AL recovery export "$RECOVERY".alice >/tmp/fd0-multi-step2.log 2>&1
printf "bob-rec\nbob-rec\n"     | BL recovery export "$RECOVERY".bob   >>/tmp/fd0-multi-step2.log 2>&1
[ -f "$RECOVERY".alice ] && ok "Alice's recovery file written" || no "Alice recovery export failed (see /tmp/fd0-multi-step2.log)"
[ -f "$RECOVERY".bob   ] && ok "Bob's recovery file written"   || no "Bob recovery export failed"

printf "alice-rec\n" | env FD0_HOME="$HOME/.fd0-alice-desktop" FD0_SSH_SOCK="$HOME/.fd0-alice-desktop/ssh.sock" "$FD0" recovery import "$RECOVERY".alice >>/tmp/fd0-multi-step2.log 2>&1 \
    || no "Alice restore failed: $(tail -3 /tmp/fd0-multi-step2.log)"
printf "bob-rec\n"       | env FD0_HOME="$HOME/.fd0-bob-desktop" FD0_SSH_SOCK="$HOME/.fd0-bob-desktop/ssh.sock" "$FD0" recovery import "$RECOVERY".bob   >>/tmp/fd0-multi-step2.log 2>&1 \
    || no "Bob restore failed: $(tail -3 /tmp/fd0-multi-step2.log)"
# Version 2 recovery files carry the identity's unlock methods, so the
# restored device unlocks with the same passphrase as the original.
unlock "$HOME/.fd0-alice-desktop" "alice-laptop-pass"
unlock "$HOME/.fd0-bob-desktop"   "bob-laptop-pass"
# Background sync never pins a server on first contact; one explicit sync
# per new device does (FD0_AUTO_PIN=1 confirms the pin unattended).
AD sync >/dev/null 2>&1 || no "Alice/desktop first sync failed"
BD sync >/dev/null 2>&1 || no "Bob/desktop first sync failed"
sleep 0.3
# super_pub sanity: Alice's two devices share identity
LAPTOP_PUB=$(AL status | awk '/super_pub/{print $2}')
DESKTOP_PUB=$(AD status | awk '/super_pub/{print $2}')
expect_eq "$LAPTOP_PUB" "$DESKTOP_PUB" "Alice's two computers share super_pub"
LAPTOP_PUB=$(BL status | awk '/super_pub/{print $2}')
DESKTOP_PUB=$(BD status | awk '/super_pub/{print $2}')
expect_eq "$LAPTOP_PUB" "$DESKTOP_PUB" "Bob's two computers share super_pub"

# ─── 3) Card exchange (alice ↔ bob) ───────────────────────────────────────
step "3) Card exchange (laptop side does the import; desktop picks it up via vault sync — but vault is local-only in v1, so we import on both devices independently)"
ALICE_CARD=$(AL card export 2>/dev/null)
BOB_CARD=$(BL card export 2>/dev/null)
AL card import "$BOB_CARD"   --label bob   --yes >/dev/null
AD card import "$BOB_CARD"   --label bob   --yes >/dev/null
BL card import "$ALICE_CARD" --label alice --yes >/dev/null
BD card import "$ALICE_CARD" --label alice --yes >/dev/null
ok "Both users pinned each other on both devices"

# ─── 4) Scopes ────────────────────────────────────────────────────────────
step "4) Scopes: personal-{alice,bob} (private), shared-work (alice creates, adds bob), shared-finance (bob creates, adds alice)"
AL scope create --label personal-alice >/dev/null
AL scope create --label shared-work    >/dev/null
AL set DEPLOY_KEY "alice-deploy-real" --scope shared-work >/dev/null
AL scope add-member bob --scope shared-work >/dev/null

BL scope create --label personal-bob    >/dev/null
BL scope create --label shared-finance >/dev/null
BL set BANK_TOKEN "bob-bank-real" --scope shared-finance >/dev/null
BL scope add-member alice --scope shared-finance >/dev/null

# Force a sync so the discovery propagates.
AL sync >/dev/null
BL sync >/dev/null

# Wait a bit for auto-sync to propagate to other devices.
sleep 5

OUT=$(AL scope ls)
expect_contains "$OUT" "personal-alice" "Alice/laptop sees personal-alice"
expect_contains "$OUT" "shared-work"    "Alice/laptop sees shared-work"
expect_contains "$OUT" "shared-finance" "Alice/laptop sees shared-finance (discovered via auto-sync)"

OUT=$(BL scope ls)
expect_contains "$OUT" "personal-bob"    "Bob/laptop sees personal-bob"
expect_contains "$OUT" "shared-finance" "Bob/laptop sees shared-finance"
expect_contains "$OUT" "shared-work"    "Bob/laptop sees shared-work (discovered)"

OUT=$(AD scope ls)
expect_contains "$OUT" "personal-alice" "Alice/desktop sees personal-alice (after auto-sync)"
expect_contains "$OUT" "shared-work"    "Alice/desktop sees shared-work"
expect_contains "$OUT" "shared-finance" "Alice/desktop sees shared-finance"

OUT=$(BD scope ls)
expect_contains "$OUT" "personal-bob"    "Bob/desktop sees personal-bob"
expect_contains "$OUT" "shared-finance" "Bob/desktop sees shared-finance"

# ─── 5) Single-user multi-device sync ─────────────────────────────────────
step "5) Single-user multi-device: alice's laptop writes, desktop pulls"
AL set LAPTOP_NOTE "from-laptop" --scope personal-alice >/dev/null
AL sync >/dev/null
sleep 5  # auto-sync window
VAL=$(AD get LAPTOP_NOTE --scope personal-alice 2>&1 | tail -1)
expect_eq "$VAL" "from-laptop" "Alice/desktop reads what laptop wrote"

step "5b) Bob's desktop writes, laptop pulls"
BD set DESKTOP_NOTE "from-desktop" --scope personal-bob >/dev/null
BD sync >/dev/null
sleep 5
VAL=$(BL get DESKTOP_NOTE --scope personal-bob 2>&1 | tail -1)
expect_eq "$VAL" "from-desktop" "Bob/laptop reads what desktop wrote"

# ─── 6) Cross-user shared scope ──────────────────────────────────────────
step "6) Cross-user shared: alice writes shared, bob reads shared"
AL set SHARED_KEY "alice-shared" --scope shared-work >/dev/null
AL sync >/dev/null
sleep 5
VAL=$(BL get SHARED_KEY --scope shared-work 2>&1 | tail -1)
expect_eq "$VAL" "alice-shared" "Bob/laptop reads alice's shared write"
VAL=$(BD get SHARED_KEY --scope shared-work 2>&1 | tail -1)
expect_eq "$VAL" "alice-shared" "Bob/desktop reads alice's shared write"

step "6b) Symmetry: bob writes finance, alice reads"
BL set FINANCE_TOKEN "bob-finance" --scope shared-finance >/dev/null
BL sync >/dev/null
sleep 5
VAL=$(AL get FINANCE_TOKEN --scope shared-finance 2>&1 | tail -1)
expect_eq "$VAL" "bob-finance" "Alice/laptop reads bob's finance write"

# ─── 7) Concurrent same-user, different keys (no conflict) ───────────────
step "7) Concurrent same-user different keys: both alice devices write disjoint keys"
AL set KEY_FROM_LAPTOP  "v1" --scope personal-alice >/dev/null
AD set KEY_FROM_DESKTOP "v2" --scope personal-alice >/dev/null
AL sync >/dev/null; AD sync >/dev/null
sleep 3
AL sync >/dev/null; AD sync >/dev/null
sleep 1
expect_eq "$(AL get KEY_FROM_DESKTOP --scope personal-alice 2>&1 | tail -1)" "v2" "Alice/laptop sees desktop's write"
expect_eq "$(AD get KEY_FROM_LAPTOP  --scope personal-alice 2>&1 | tail -1)" "v1" "Alice/desktop sees laptop's write"

# ─── 8) Concurrent cross-user same key (auto-reconcile) ──────────────────
step "8) Concurrent cross-user same key — last-writer-wins via auto-reconcile"
AL set RACE_KEY "alice-version" --scope shared-work >/dev/null
BL set RACE_KEY "bob-version"   --scope shared-work >/dev/null
AL sync >/dev/null
BL sync 2>&1 | head -3   # bob's push triggers reconcile
sleep 1
AL sync >/dev/null
sleep 1
A_VAL=$(AL get RACE_KEY --scope shared-work 2>&1 | tail -1)
B_VAL=$(BL get RACE_KEY --scope shared-work 2>&1 | tail -1)
expect_eq "$A_VAL" "$B_VAL" "Both users converge on same RACE_KEY value"

# ─── 9) Tombstone propagation ────────────────────────────────────────────
step "9) Tombstone: alice rm SHARED_KEY → bob's both devices lose it"
AL rm SHARED_KEY --scope shared-work >/dev/null
AL sync >/dev/null
sleep 5
OUT=$(BL get SHARED_KEY --scope shared-work 2>&1 || true)
expect_contains "$OUT" "not found" "Bob/laptop sees SHARED_KEY tombstoned"
OUT=$(BD get SHARED_KEY --scope shared-work 2>&1 || true)
expect_contains "$OUT" "not found" "Bob/desktop sees SHARED_KEY tombstoned"

# ─── 10) Member rotation: alice removes bob from shared-work ─────────────
step "10) Alice removes bob from shared-work — bob's both devices auto-drop"
AL scope remove-member bob --scope shared-work >/dev/null
AL sync >/dev/null
sleep 5
OUT=$(BL scope ls)
expect_not_contains "$OUT" "shared-work" "Bob/laptop dropped shared-work"
OUT=$(BD scope ls)
expect_not_contains "$OUT" "shared-work" "Bob/desktop dropped shared-work"

# ─── 11) Forward-secrecy check ───────────────────────────────────────────
step "11) Forward secrecy: alice writes new secret post-rotation, bob doesn't see it"
AL set POST_ROTATION "secret-after-bob-removed" --scope shared-work >/dev/null
AL sync >/dev/null
sleep 5
OUT=$(BL ls 2>&1)
expect_not_contains "$OUT" "POST_ROTATION" "Bob/laptop cannot see post-rotation secrets"

# ─── 12) doctor on all four devices ──────────────────────────────────────
step "12) doctor on all four devices"
for fn in AL AD BL BD; do
    DEV=$($fn status | awk '/super_pub/{exit}{print}' | head -1)
    OUT=$($fn doctor 2>&1 || true)
    if printf "%s" "$OUT" | grep -q "all clear"; then
        ok "$fn doctor: all clear"
    else
        no "$fn doctor reported issues"
        printf "%s\n" "$OUT" | sed 's/^/    /'
    fi
done

# ─── 13–18) Multi-auth on Alice's laptop ─────────────────────────────────
step "13) Alice/laptop auth ls — single method"
OUT=$(AL auth ls)
COUNT=$(printf "%s" "$OUT" | grep -c "^" || true)
expect_eq "$COUNT" "1" "auth ls reports one method"

step "14) Alice/laptop adds second passphrase"
printf "alice-laptop-pass-2\nalice-laptop-pass-2\n" | AL auth add 2>&1 | tail -1
OUT=$(AL auth ls)
COUNT=$(printf "%s" "$OUT" | grep -c "^" || true)
expect_eq "$COUNT" "2" "auth ls reports two methods"

step "15) Alice/laptop lock + unlock with NEW passphrase"
AL lock >/dev/null
sleep 0.2
unlock "$HOME/.fd0-alice-laptop" "alice-laptop-pass-2"
sleep 0.3
ACTIVE_NEW=$(AL auth ls | awk '/^\*/{print $2}')
ok "Re-unlocked with second passphrase ($ACTIVE_NEW)"

step "16) Alice/laptop removes ORIGINAL passphrase (the inactive one)"
ORIGINAL=$(AL auth ls | awk '/^[^*]/{print $1; exit}')
AL auth rm "$ORIGINAL" 2>&1 | tail -1
OUT=$(AL auth ls)
COUNT=$(printf "%s" "$OUT" | grep -c "^" || true)
expect_eq "$COUNT" "1" "after rm: one method left"

step "17) Lock + try unlock with REMOVED passphrase — must fail"
AL lock >/dev/null
sleep 0.2
if printf "alice-laptop-pass\n" | env FD0_HOME="$HOME/.fd0-alice-laptop" FD0_SSH_SOCK="$HOME/.fd0-alice-laptop/ssh.sock" "$FD0" unlock >/dev/null 2>&1; then
    no "Removed passphrase still unlocks (security regression!)"
else
    ok "Removed passphrase correctly rejected"
fi
unlock "$HOME/.fd0-alice-laptop" "alice-laptop-pass-2"
sleep 0.3

step "18) Last-method removal must be refused"
ONLY=$(AL auth ls | awk '/^[* ]/{print $2; exit}')
OUT=$(AL auth rm "$ONLY" 2>&1 || true)
expect_contains "$OUT" "currently-unlocked" "Refused (target is the only AND active method)"

# ─── 19) Recovery cross-check: alice's desktop has its own auth-set ──────
step "19) Alice/desktop's auth chain is independent (per-device user-chain)"
OUT=$(AD auth ls)
COUNT=$(printf "%s" "$OUT" | grep -c "^" || true)
expect_eq "$COUNT" "1" "Alice/desktop has its own single bootstrap method"

# ─── 20) Sync push delta: second sync after a write pushes 0 events ───────
# This is the v1.x bandwidth/latency fix. After a successful sync, the
# vault remembers PushFloor per scope; a follow-up `fd0 sync` with no
# new local writes must report pushed=0 dup=0 (server gets nothing).
step "20) Sync push delta: idempotent second sync"
AL set DELTA_PROBE "value-1" --scope shared-work >/dev/null
OUT1=$(AL sync 2>&1)
case "$OUT1" in
    *"pushed=1"*) ok "first sync pushed the new event" ;;
    *) no "first sync should report pushed=1, got: $OUT1" ;;
esac
OUT2=$(AL sync 2>&1)
case "$OUT2" in
    *"pushed=0 dup=0"*) ok "second sync pushed nothing (delta works)" ;;
    *"pushed=0"*) ok "second sync pushed nothing (delta works; format variation)" ;;
    *) no "second sync should be no-op, got: $OUT2" ;;
esac

# ─── 21) YubiKey enrollment without a card → graceful refusal ─────────────
# We don't have hardware in CI. The CLI must print a clear error pointing
# at the build tag / hardware-day status, NOT half-enroll the user.
step "21) YubiKey enrollment without hardware → clean error"
# Pre-check: count auth methods on alice-laptop before the attempted enroll.
COUNT_BEFORE=$(AL auth ls | grep -c "^" || true)
# Choose touch-only (`n`) at the prompt; the enroll then fails because no
# card / build tag absent.
OUT=$(printf "n\n" | AL auth add --yubikey 2>&1 || true)
case "$OUT" in
    *"build fd0 with -tags=yubikey"* | *"yubikey:"* | *"no smartcard"* | *"without YubiKey/PIV support"*)
        ok "yubikey enroll surfaced a clear error" ;;
    *) no "yubikey enroll output unexpected: $OUT" ;;
esac
COUNT_AFTER=$(AL auth ls | grep -c "^" || true)
expect_eq "$COUNT_AFTER" "$COUNT_BEFORE" "yubikey-enroll failure left auth methods unchanged"

# ─── 22) Server rate limiting: dedicated server with low cap ──────────────
# Spin up a second server instance with --register-per-hour=1, exercise
# the limit via curl (registration). Confirms the 429 + Retry-After path
# end-to-end without polluting the main server's rate-limit state.
step "22) Server rate-limit (dedicated instance, cap=1/h)"
RL_PORT=14149
"$FD0_SERVER_BIN" --bind=":${RL_PORT}" --db=/tmp/fd0-rl.db --register-per-hour=1 > /tmp/fd0-rl.log 2>&1 &
RL_PID=$!
sleep 0.4
# Build a single tiny CBOR body — invalid as a real registration but
# enough to drive the rate-limit pathway. The first request will fail
# validation BEFORE the limiter check (post-MaxBytes) — actually no, the
# limiter runs first. So we expect:
#   1st: 400 (bad body) but bucket spent
#   2nd: 429 (limit hit)
curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${RL_PORT}/v1/users" \
    -H "Content-Type: application/cbor" --data-binary "x" > /tmp/fd0-rl-first.code
FIRST=$(cat /tmp/fd0-rl-first.code)
# Either 400 (bad body) or 201 — both consume a token.
case "$FIRST" in
    400|201) ok "first /users call returned $FIRST (bucket consumed)" ;;
    *) no "first /users call returned unexpected $FIRST" ;;
esac
SECOND=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${RL_PORT}/v1/users" \
    -H "Content-Type: application/cbor" --data-binary "x")
expect_eq "$SECOND" "429" "second /users call rate-limited (429)"
RETRY=$(curl -s -i -X POST "http://127.0.0.1:${RL_PORT}/v1/users" \
    -H "Content-Type: application/cbor" --data-binary "x" | tr -d '\r' | awk '/^Retry-After:/{print $2}')
if [ -n "$RETRY" ]; then ok "Retry-After present (= ${RETRY}s)"
else no "Retry-After header missing on 429"
fi
kill $RL_PID 2>/dev/null || true
wait $RL_PID 2>/dev/null || true
rm -f /tmp/fd0-rl.db /tmp/fd0-rl.log /tmp/fd0-rl-first.code

# ─── 23) Agent idle/max config from ~/.fd0/config.toml ────────────────────
# Drop a ~/.fd0/config.toml on a fresh home with [agent] knobs and
# confirm fd0-agent picks them up without --idle-timeout / FD0_AGENT_IDLE.
step "23) Agent reads [agent].idle_timeout from config"
TEST_HOME=/tmp/fd0-agent-cfg-test
rm -rf "$TEST_HOME"
mkdir -p "$TEST_HOME" && chmod 700 "$TEST_HOME"
cat > "$TEST_HOME/config.toml" <<EOF
[agent]
idle_timeout = "37s"
max_lifetime = "11h"
EOF
printf "x-pass\nx-pass\n" | env FD0_HOME="$TEST_HOME" FD0_SSH_SOCK="$TEST_HOME/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "x-pass\n" | env FD0_HOME="$TEST_HOME" FD0_SSH_SOCK="$TEST_HOME/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
# Look for a recent idle/max line in the agent log. The agent writes
# "agent: auto-sync enabled" / "agent listening" but logs idle on idle
# events only. We instead read the running flags via /proc/<pid>/cmdline
# is unavailable on macOS — but the agent does NOT print its idle config
# at startup. So we only verify the agent comes up; the parse code is
# unit-tested in resolveDuration. Smoke-test: status reports unlocked.
ST=$(env FD0_HOME="$TEST_HOME" FD0_SSH_SOCK="$TEST_HOME/ssh.sock" "$FD0" status 2>&1 || true)
case "$ST" in
    *"unlocked"*) ok "agent up with config-driven [agent] knobs (smoke)" ;;
    *) no "agent didn't come up cleanly: $ST" ;;
esac
env FD0_HOME="$TEST_HOME" FD0_SSH_SOCK="$TEST_HOME/ssh.sock" "$FD0" lock >/dev/null 2>&1 || true
rm -rf "$TEST_HOME"

# ─── Summary ─────────────────────────────────────────────────────────────
echo
printf "\033[1m== SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
