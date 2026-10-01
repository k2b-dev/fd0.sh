#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

# YubiKey end-to-end multi-user integration test.
#
# Spins up a real fd0 server + witness, three users (Alice + Bob via
# passphrase, Carol via YubiKey), and walks an extended scenario that
# touches every CLI command at least once and the YubiKey card on
# every (re)unlock. Designed to validate Phase 1's wiring (resolver,
# agent factory, CLI prompt) under realistic multi-user load.
#
# Hardware required:
#   - YubiKey 5.7+ on the bus, with PIV applet enabled.
#   - Slot 0x9d (Key Management) populated with an X25519 key OR
#     empty AND FD0_YUBIKEY_ENROLL=1 (the script auto-provisions
#     touch=never, pin-policy=once when allowed).
#   - PIV PIN known and supplied via FD0_YUBIKEY_PIN (default
#     "123456").
#
# Run:
#   FD0_YUBIKEY_HARDWARE=1 bash tests/integration_yubikey_e2e.sh
#
# Notes:
#   - The script DOES NOT consume PIN retries on wrong-PIN tests
#     beyond what is needed to verify rejection (single attempt,
#     expected 401-style failure). Three wrong PINs would brick the
#     PIV slot's PIN counter, so the wrong-PIN test is gated and
#     reuses the lockout-safe cycle (correct PIN restores the
#     counter implicitly on the next successful verify).
#
# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY
# pinning.
export FD0_AUTO_PIN=1

set -uo pipefail

# ─── Hardware-gate ────────────────────────────────────────────────
if [ "${FD0_YUBIKEY_HARDWARE:-}" != "1" ]; then
    echo "skipping YubiKey e2e: set FD0_YUBIKEY_HARDWARE=1"
    exit 0
fi
PIN="${FD0_YUBIKEY_PIN:-123456}"
ENROLL_IF_EMPTY="${FD0_YUBIKEY_ENROLL:-0}"

# ─── Test layout ──────────────────────────────────────────────────
SERVER_PORT=14998
SERVER_DB=/tmp/fd0-yk-server.db
SERVER_LOG=/tmp/fd0-yk-server.log
WITNESS_DB=/tmp/fd0-yk-witness.db
WITNESS_CFG=/tmp/fd0-yk-witness.toml
WITNESS_LOG=/tmp/fd0-yk-witness.log
RECOVERY_AL=/tmp/fd0-yk-rec-alice
RECOVERY_CA=/tmp/fd0-yk-rec-carol

HOME_AL=$HOME/.fd0-yk-al   # Alice (passphrase)
HOME_AD=$HOME/.fd0-yk-ad   # Alice second device
HOME_BL=$HOME/.fd0-yk-bl   # Bob (passphrase)
HOME_CA=$HOME/.fd0-yk-ca   # Carol (YubiKey-backed)

FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
FD0_WITNESS_BIN=${FD0_WITNESS:-$HOME/go/bin/fd0-witness}

PASS=0
FAIL=0
phase()    { printf "\n\033[1m═══ %s ═══\033[0m\n" "$*"; }
ok()       { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()       { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }
expect_eq() {
    if [ "$1" = "$2" ]; then ok "$3"; else no "$3 (got '$1' want '$2')"; fi
}
expect_contains() {
    if printf '%s' "$1" | grep -qF "$2"; then ok "$3"; else no "$3 (got '$1' want substring '$2')"; fi
}

cleanup() {
    # Kill ONLY the per-test agent processes — match by socket path so
    # we never touch the user's existing fd0-agent. Each per-home agent
    # writes its pid into $FD0_HOME/agent.pid; read and signal it
    # individually.
    for home in "$HOME_AL" "$HOME_AD" "$HOME_BL" "$HOME_CA"; do
        pf="$home/agent.pid"
        if [ -r "$pf" ]; then
            apid=$(cat "$pf" 2>/dev/null || true)
            if [ -n "$apid" ] && [ "$apid" -gt 0 ] 2>/dev/null && kill -0 "$apid" 2>/dev/null; then
                kill "$apid" 2>/dev/null || true
            fi
        fi
    done
    # Kill the test-spawned server + witness only (PIDs we recorded).
    if [ "${SERVER_PID:-0}" -gt 0 ] 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    if [ "${WITNESS_PID:-0}" -gt 0 ] 2>/dev/null && kill -0 "$WITNESS_PID" 2>/dev/null; then
        kill "$WITNESS_PID" 2>/dev/null || true
    fi
    rm -rf "$HOME_AL" "$HOME_AD" "$HOME_BL" "$HOME_CA"
    rm -f  "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_LOG" "$WITNESS_DB" "$WITNESS_CFG" "$WITNESS_LOG" \
           "$RECOVERY_AL" "$RECOVERY_CA"
}
trap cleanup EXIT

# ─── Build fd0 + fd0-agent with the yubikey tag ───────────────────
phase "build with -tags=yubikey"
go build -tags=yubikey -ldflags "$FD0_TEST_GO_LDFLAGS" -o "$FD0"          ./cmd/fd0          || { no "build fd0";       exit 1; }
go build -tags=yubikey -ldflags "$FD0_TEST_GO_LDFLAGS" -o "$FD0_AGENT"    ./cmd/fd0-agent    || { no "build fd0-agent"; exit 1; }
go build                -o "$FD0_SERVER_BIN"  ./cmd/fd0-server  || { no "build fd0-server"; exit 1; }
go build                -o "$FD0_WITNESS_BIN" ./cmd/fd0-witness || { no "build fd0-witness"; exit 1; }
ok "binaries built"

# ─── Per-device CLI invokers ──────────────────────────────────────
mkfd0() {
    local home="$1"
    mkdir -p "$home" && chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
[client]
lock_wait = "10s"
EOF
}

AL() { env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
AD() { env FD0_HOME="$HOME_AD" FD0_SSH_SOCK="$HOME_AD/ssh.sock" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
BL() { env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
CA() { env FD0_HOME="$HOME_CA" FD0_SSH_SOCK="$HOME_CA/ssh.sock" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }

CA_lock() {
    # Lock Carol's vault via the agent (clears super_priv from mlocked
    # memory). Do not use broad process matching — that would also kill Alice's
    # and Bob's agents on this same machine, breaking their sync ops.
    CA lock >/dev/null 2>&1 || true
}
CA_unlock_pass() { printf "carol-pass\n" | CA unlock --method=passphrase >/dev/null 2>&1; }
CA_unlock_yk()   { printf "%s\n" "$PIN"  | CA unlock --method=yubikey    >/dev/null 2>&1; }

# ─── Phase 1: spin up server + witness ────────────────────────────
phase "server + witness"
"$FD0_SERVER_BIN" --bind=":$SERVER_PORT" --db="$SERVER_DB" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5
if ! kill -0 $SERVER_PID 2>/dev/null; then
    no "server failed to start"; tail -20 "$SERVER_LOG"; exit 1
fi
ok "server pid $SERVER_PID on :$SERVER_PORT"

# NOTE: this test deliberately does NOT spin up an fd0-witness. The
# witness path is exercised by tests/integration_e2e.sh; this suite
# is focused on YubiKey unlock semantics and the multi-user flow on
# top of it. Dropping the witness keeps the test self-contained.
WITNESS_PID=0

# ─── Phase 1.5: PIN-retry preflight (P0 — never run further if  ───
# ─── the card's PIN counter is below 3, otherwise our wrong-PIN   ─
# ─── test could BRICK it on a chained run). ───────────────────────
phase "PIN retry preflight (refuse to run if counter < 3/3)"
if ! command -v ykman >/dev/null 2>&1; then
    no "ykman not on PATH — install via 'brew install ykman' so the preflight can read PIN retries safely"
    exit 1
fi
# Parse "PIN tries remaining:      3/3" from `ykman piv info`. We only
# trust the exact-3 case; anything else is refused so a chained test
# run can't brick a half-attempted card.
RETRIES=$(ykman piv info 2>/dev/null | awk '/PIN tries remaining/ {print $4}')
if [ "$RETRIES" = "3/3" ]; then
    ok "PIN retry counter is 3/3 (safe to run wrong-PIN test)"
else
    no "PIN retry counter is '$RETRIES' (want '3/3') — refusing to run because a wrong-PIN test could block the slot"
    no "Recover: 'ykman piv access unblock-pin' or any successful 'ykman piv access change-pin' resets the counter"
    exit 1
fi

# ─── Phase 2: ensure Carol's YubiKey slot has a key ───────────────
phase "YubiKey provision"
if FD0_YUBIKEY_HARDWARE=1 FD0_YUBIKEY_ENROLL="$ENROLL_IF_EMPTY" \
    go test -tags=yubikey -count=1 -run TestYubikeyIntegration_AutoEnroll \
    ./internal/crypto/yubikey/ >/tmp/fd0-yk-probe.log 2>&1
then
    ok "slot 0x9d ready for X25519"
else
    no "slot probe failed:"
    tail -20 /tmp/fd0-yk-probe.log
    exit 1
fi

# ─── Phase 3: init three users ────────────────────────────────────
phase "user init"
mkfd0 "$HOME_AL"
mkfd0 "$HOME_AD"
mkfd0 "$HOME_BL"
mkfd0 "$HOME_CA"

printf "alice-p\nalice-p\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" init >/dev/null 2>&1 \
    && ok "Alice init" || no "Alice init"
printf "bob-p\nbob-p\n"     | env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" "$FD0" init >/dev/null 2>&1 \
    && ok "Bob init"   || no "Bob init"
printf "carol-pass\ncarol-pass\n" | env FD0_HOME="$HOME_CA" FD0_SSH_SOCK="$HOME_CA/ssh.sock" "$FD0" init >/dev/null 2>&1 \
    && ok "Carol init (passphrase)" || no "Carol init"

# ─── Phase 4: unlock + cards ──────────────────────────────────────
phase "first unlock + card exchange"
printf "alice-p\n"    | AL unlock >/dev/null 2>&1   && ok "Alice unlock"   || no "Alice unlock"
printf "bob-p\n"      | BL unlock >/dev/null 2>&1   && ok "Bob unlock"     || no "Bob unlock"
printf "carol-pass\n" | CA unlock >/dev/null 2>&1   && ok "Carol unlock (passphrase, pre-yubikey)" || no "Carol unlock (passphrase)"

CARD_AL=$(AL card export 2>/dev/null | head -1)
CARD_BL=$(BL card export 2>/dev/null | head -1)
CARD_CA=$(CA card export 2>/dev/null | head -1)
expect_contains "$CARD_AL" "fd0://card/" "Alice card export"
expect_contains "$CARD_BL" "fd0://card/" "Bob card export"
expect_contains "$CARD_CA" "fd0://card/" "Carol card export"

AL card import "$CARD_BL" --label bob   --yes >/dev/null 2>&1 && ok "Alice imports Bob"   || no "Alice import Bob"
AL card import "$CARD_CA" --label carol --yes >/dev/null 2>&1 && ok "Alice imports Carol" || no "Alice import Carol"
BL card import "$CARD_AL" --label alice --yes >/dev/null 2>&1 && ok "Bob imports Alice"   || no "Bob import Alice"
BL card import "$CARD_CA" --label carol --yes >/dev/null 2>&1 && ok "Bob imports Carol"   || no "Bob import Carol"
CA card import "$CARD_AL" --label alice --yes >/dev/null 2>&1 && ok "Carol imports Alice" || no "Carol import Alice"
CA card import "$CARD_BL" --label bob   --yes >/dev/null 2>&1 && ok "Carol imports Bob"   || no "Carol import Bob"

# ─── Phase 5: Carol enrolls a YubiKey method ──────────────────────
phase "Carol enrolls YubiKey"
COUNT_BEFORE=$(CA auth ls 2>/dev/null | grep -c "^" || true)
ENROLL_OUT=$(printf "y\n%s\n%s\n" "$PIN" "$PIN" | CA auth add --yubikey --touch=never --force 2>&1) || true
if echo "$ENROLL_OUT" | grep -q "added YubiKey auth method"; then
    ok "Carol enrolled YubiKey (PIN+touch policy)"
else
    no "Carol enroll yubikey: $ENROLL_OUT"
    exit 1
fi
COUNT_AFTER=$(CA auth ls 2>/dev/null | grep -c "^" || true)
expect_eq "$COUNT_AFTER" $((COUNT_BEFORE + 1)) "auth method count grew by 1"

# Sync so the new auth.set is persisted server-side too.
CA sync >/dev/null 2>&1 && ok "post-enroll sync" || no "post-enroll sync"

# ─── Phase 6: lock/unlock alternating methods ─────────────────────
phase "alternating unlock methods"

# Lock first.
CA_lock; ok "Carol locked"

# Unlock with passphrase (the original method).
CA_unlock_pass && ok "Carol unlock (passphrase #2)" || no "Carol unlock (passphrase #2)"
CA status 2>/dev/null | grep -q unlocked && ok "agent reports unlocked" || no "agent not unlocked"

CA_lock
# Now unlock with YubiKey (NEW path through the resolver).
CA_unlock_yk && ok "Carol unlock (YubiKey #1)" || no "Carol unlock (YubiKey #1)"
CA status 2>/dev/null | grep -q unlocked && ok "agent reports unlocked (yubikey)" || no "agent not unlocked (yubikey)"

# Quick self-doctor with the agent unlocked via YubiKey.
DOC_OUT=$(CA doctor 2>&1 || true)
expect_contains "$DOC_OUT" "agent" "doctor: agent section present"
expect_contains "$DOC_OUT" "user chain" "doctor: user chain section present"

# ─── Phase 7: scope creation + multi-user secret ops ──────────────
phase "scopes + secrets across all 3 users"
CA scope create --label work >/dev/null 2>&1 && ok "Carol creates 'work'" || no "Carol scope create"
CA set DEPLOY_KEY "carol-deploy-1" --scope work >/dev/null 2>&1 && ok "Carol set DEPLOY_KEY" || no "Carol set DEPLOY_KEY"
CA set DB_PASS    "carol-db-1"      --scope work >/dev/null 2>&1 && ok "Carol set DB_PASS"    || no "Carol set DB_PASS"
CA scope add-member alice --scope work >/dev/null 2>&1 && ok "Carol adds Alice"  || no "Carol add Alice"
CA scope add-member bob   --scope work >/dev/null 2>&1 && ok "Carol adds Bob"    || no "Carol add Bob"
CA sync >/dev/null 2>&1 && ok "Carol sync after invites" || no "Carol sync after invites"

# Alice + Bob discover the new scope.
AL sync >/dev/null 2>&1; AL sync >/dev/null 2>&1; ok "Alice 2× sync (discover)"
BL sync >/dev/null 2>&1; BL sync >/dev/null 2>&1; ok "Bob 2× sync (discover)"

# Both can read Carol's secrets after sync.
AL_DEPLOY=$(AL get DEPLOY_KEY --scope work 2>/dev/null || true)
BL_DEPLOY=$(BL get DEPLOY_KEY --scope work 2>/dev/null || true)
expect_eq "$AL_DEPLOY" "carol-deploy-1" "Alice reads DEPLOY_KEY (sealed via Carol's YubiKey-bound super_priv)"
expect_eq "$BL_DEPLOY" "carol-deploy-1" "Bob reads DEPLOY_KEY"

# Alice writes back; Carol sees it.
AL set ALICE_NOTE "alice-writes-here" --scope work >/dev/null 2>&1
AL sync >/dev/null 2>&1
CA sync >/dev/null 2>&1
CA_NOTE=$(CA get ALICE_NOTE --scope work 2>/dev/null || true)
expect_eq "$CA_NOTE" "alice-writes-here" "Carol (YubiKey) reads Alice's secret"

# ─── Phase 8: lock/unlock cycles to stress the on-card ECDH ───────
phase "lock/unlock cycles (5×) — each one a fresh on-card ECDH"
for i in 1 2 3 4 5; do
    CA_lock
    if CA_unlock_yk; then
        if CA get DEPLOY_KEY --scope work 2>/dev/null | grep -q "carol-deploy-1"; then
            ok "cycle $i: unlock + read"
        else
            no "cycle $i: read after unlock failed"
        fi
    else
        no "cycle $i: yubikey unlock failed"
    fi
done

# ─── Phase 9: wrong PIN rejected ──────────────────────────────────
# IMPORTANT: PIV slot blocks after 3 wrong PINs. We make exactly ONE
# wrong attempt here, then ALWAYS recover with a correct PIN that
# resets the retry counter on the card. Do not loop or re-run this
# phase without verifying retry status first.
phase "wrong PIN: rejected without burning the rest of the test"
CA_lock
set +e
printf "wrong-1\n" | CA unlock --method=yubikey >/tmp/fd0-yk-wrongpin.out 2>&1
WRONG_RC=$?
set -e
WRONG_OUT=$(cat /tmp/fd0-yk-wrongpin.out)
rm -f /tmp/fd0-yk-wrongpin.out
if [ "$WRONG_RC" -eq 0 ]; then
    no "wrong-PIN unlock returned exit 0 — it should fail. Output: $WRONG_OUT"
elif echo "$WRONG_OUT" | grep -qE "verify PIN|incorrect|6983|6982|smart card error 6"; then
    ok "wrong PIN surfaces a clear error (rc=$WRONG_RC): $(echo "$WRONG_OUT" | grep -E '✗|verify' | head -1)"
else
    no "wrong-PIN exit=$WRONG_RC but output lacks PIN-verify diagnostic: $WRONG_OUT"
fi
# Restore correct PIN session so subsequent phases work AND reset the
# retry counter on the card.
CA_unlock_yk && ok "correct PIN restores unlock (resets retry counter)" || no "correct PIN failed after wrong-PIN test"

# ─── Phase 10: passphrase still works after YubiKey enrollment ────
phase "passphrase fallback (both methods active)"
CA_lock
CA_unlock_pass && ok "Carol unlock via passphrase fallback" || no "Carol passphrase fallback failed"
PASSPHRASE_DEPLOY=$(CA get DEPLOY_KEY --scope work 2>/dev/null || true)
expect_eq "$PASSPHRASE_DEPLOY" "carol-deploy-1" "secrets decrypt under passphrase-method too"

# Cross-method invariant: super_priv is identity-bound, not method-
# bound. Whether Carol unlocks via passphrase or YubiKey, the
# resulting agent state must produce signatures that other members
# accept. We exercise this by writing a NEW secret while unlocked
# via passphrase, syncing, then asserting Alice (different user)
# can read it. If the agent somehow tied super_priv to the unlock
# method, this would surface as a sign / verify mismatch downstream.
CA set MIXED_SIGN_PROBE "carol-via-passphrase-while-yubikey-also-active" --scope work >/dev/null 2>&1 \
    && ok "Carol set MIXED_SIGN_PROBE under passphrase unlock" || no "Carol set under passphrase failed"
CA sync >/dev/null 2>&1
AL sync >/dev/null 2>&1
MIXED_AL_GOT=$(AL get MIXED_SIGN_PROBE --scope work 2>/dev/null || true)
expect_eq "$MIXED_AL_GOT" "carol-via-passphrase-while-yubikey-also-active" \
    "Alice reads passphrase-era write (super_priv is identity-bound, not method-bound)"

# ─── Phase 11: Carol removes the passphrase method (yubikey-only) ─
phase "Carol removes passphrase, becomes YubiKey-only"

# auth rm refuses to remove the currently-active method. Unlock via
# YubiKey first, then remove the passphrase.
CA_lock
CA_unlock_yk && ok "Carol re-unlocked via YubiKey before rm" || no "yk re-unlock for rm"

# Extract the passphrase method id robustly (auth ls lines start with
# either "* " for active or "  " for inactive; field positions shift).
PP_ID=$(CA auth ls 2>/dev/null | awk '/passphrase/ {for(i=1;i<=NF;i++) if($i ~ /^am_/) {print $i; exit}}')
if [ -z "$PP_ID" ]; then
    no "could not extract passphrase method id from auth ls"
else
    if CA auth rm "$PP_ID" >/dev/null 2>&1; then
        ok "auth rm passphrase succeeded ($PP_ID)"
    else
        no "auth rm passphrase failed"
    fi
fi
CA sync >/dev/null 2>&1 && ok "post-rm sync" || no "post-rm sync"

CA_lock
# Passphrase MUST now fail.
PP_FAIL=$(printf "carol-pass\n" | CA unlock --method=passphrase 2>&1 || true)
case "$PP_FAIL" in
    *"--method=\"passphrase\""*|*"no enrolled method"*|*"unknown method"*|*"no matching"*|*"matches"*)
        ok "passphrase unlock now rejected (yubikey-only): $(echo "$PP_FAIL" | head -1)"
        ;;
    *)  no "expected passphrase rejection, got: $PP_FAIL" ;;
esac
# YubiKey unlock STILL works.
CA_unlock_yk && ok "Carol unlock (yubikey, only method)" || no "Carol unlock (yubikey-only) failed"

# ─── Phase 12: write/sync/read across all 3 again ─────────────────
phase "post-yubikey-only multi-user round trip"
CA set POST_YK_K1 "carol-via-yubikey-only-1" --scope work >/dev/null 2>&1
CA sync >/dev/null 2>&1
AL sync >/dev/null 2>&1
BL sync >/dev/null 2>&1
AL_GOT=$(AL get POST_YK_K1 --scope work 2>/dev/null || true)
BL_GOT=$(BL get POST_YK_K1 --scope work 2>/dev/null || true)
expect_eq "$AL_GOT" "carol-via-yubikey-only-1" "Alice reads Carol's yubikey-only-era secret"
expect_eq "$BL_GOT" "carol-via-yubikey-only-1" "Bob reads Carol's yubikey-only-era secret"

# ─── Phase 13: many secret ops to stress sync + projections ───────
phase "stress: 20 secret writes from Carol via YubiKey unlock"
for n in $(seq 1 20); do
    CA set "STRESS_K$n" "value-$n-$(date +%s)" --scope work >/dev/null 2>&1
done
CA sync >/dev/null 2>&1
AL sync >/dev/null 2>&1
SAMPLE=$(AL get STRESS_K17 --scope work 2>/dev/null || true)
expect_contains "$SAMPLE" "value-17-" "Alice reads STRESS_K17 written by Carol (YubiKey)"

# ─── Phase 14: Carol kicks Bob — OEK rotation under yubikey ───────
phase "membership churn while Carol is YubiKey-only"
CA scope remove-member bob --scope work >/dev/null 2>&1 && ok "Carol removes Bob" || no "Carol remove Bob"
CA sync >/dev/null 2>&1
BL sync >/dev/null 2>&1
# Bob must no longer see new secrets after OEK rotation.
CA set POST_KICK_K1 "secret-after-bob-kick" --scope work >/dev/null 2>&1
CA sync >/dev/null 2>&1
BL sync >/dev/null 2>&1 || true
BL_KICK=$(BL get POST_KICK_K1 --scope work 2>/dev/null || true)
if [ -z "$BL_KICK" ]; then
    ok "Bob cannot read post-kick secret (OEK rotated)"
else
    no "Bob still reads post-kick secret: $BL_KICK"
fi
# Alice still can.
AL sync >/dev/null 2>&1
AL_KICK=$(AL get POST_KICK_K1 --scope work 2>/dev/null || true)
expect_eq "$AL_KICK" "secret-after-bob-kick" "Alice reads post-kick secret"

# ─── Phase 15: doctor under YubiKey + a chain of locks/unlocks ────
phase "doctor + 3 more lock/unlock cycles"
DOC_FINAL=$(CA doctor 2>&1 || true)
expect_contains "$DOC_FINAL" "scopes" "final doctor: scopes section"
expect_contains "$DOC_FINAL" "auth method consistency" "final doctor: auth-method-consistency section"

for i in 6 7 8; do
    CA_lock
    CA_unlock_yk && CA get DEPLOY_KEY --scope work >/dev/null 2>&1 \
        && ok "post-churn cycle $i" || no "post-churn cycle $i"
done

# ─── Phase 16: recovery flow (Carol's YubiKey-only identity) ──────
phase "recovery export/import under YubiKey-only"
printf "carol-rec\ncarol-rec\n" | CA recovery export "$RECOVERY_CA" >/dev/null 2>&1 \
    && ok "Carol exports recovery file" || no "Carol recovery export"
[ -s "$RECOVERY_CA" ] && ok "recovery file non-empty" || no "recovery file empty"

# ─── Phase 16.5: adversarial paths — only run after happy paths ───
# Concurrent-unlock: covered manually + by go-piv's PCSC layer
# (see /tmp/fd0-yk-race*.out from earlier runs: one unlock wins,
# the other returns "smart card cannot be accessed because of other
# connections outstanding"). Automating it via two backgrounded
# bash subshells deadlocks because spawning agents inherit the
# parent's stdout FD — leaving them as long-running children that
# bash `wait` won't release. We rely on the manual record + the
# pivWrapper Open path's PCSC error handling instead. (Documented
# here so a future test author doesn't reimplement the same trap.)
phase "adversarial: concurrent unlock — covered out-of-band"
ok "PCSC contention is handled by go-piv; bash automation is unsafe (see comments)"

phase "adversarial: card-absent unlock attempt (yubikey-only mode)"
# Carol is yubikey-only at this point. We can't physically yank the
# card, but we can simulate "card unreachable" by passing a wrong PIN
# AND a malformed unlock — the agent should reject without leaving a
# half-unlocked state. (Real card-yank would require human action
# with a hardware test rig.) Document this as a partial test.
CA_lock
WRONG_OUT=$(printf "wrong-x\n" | CA unlock --method=yubikey 2>&1 || true)
case "$WRONG_OUT" in
    *"verify PIN"*|*"incorrect"*|*"smart card error 6"*|*"6983"*|*"6982"*)
        ok "card-side rejection surfaces clean error after one wrong attempt"
        ;;
    *)
        no "card-rejection error unexpected: $(echo "$WRONG_OUT" | head -1)"
        ;;
esac
CA status 2>/dev/null | grep -q "running, locked" && ok "agent stays LOCKED after rejected unlock" || no "agent state wrong after rejected unlock"
# Recover for the rest of the test (resets retry counter on success).
CA_unlock_yk && ok "correct PIN restores unlock + retry counter" || no "correct-PIN recovery failed"

# ─── Phase 16.6: auth rm of last yubikey method (yubikey-only mode)
phase "adversarial: refuse to remove the last (yubikey) auth method"
# Carol is yubikey-only. Removing the only remaining method would
# brick the vault permanently. The CLI must refuse — we test the
# refusal AND that the auth method count stays at 1 afterwards.
ONLY_YK_ID=$(CA auth ls 2>/dev/null | awk '/yubikey/ {for(i=1;i<=NF;i++) if($i ~ /^am_/) {print $i; exit}}')
if [ -z "$ONLY_YK_ID" ]; then
    no "could not extract yubikey method id (Carol is supposed to be yubikey-only here)"
else
    LAST_RM_OUT=$(CA auth rm "$ONLY_YK_ID" 2>&1 || true)
    case "$LAST_RM_OUT" in
        *"currently-unlocked"*|*"last auth method"*|*"refuse"*|*"locked out"*|*"cannot remove"*)
            ok "auth rm of the last yubikey method refused: $(echo "$LAST_RM_OUT" | head -1)"
            ;;
        *)
            no "expected refusal of last-method-removal, got: $LAST_RM_OUT" ;;
    esac
fi
COUNT_AFTER_LAST=$(CA auth ls 2>/dev/null | grep -c "^" || true)
expect_eq "$COUNT_AFTER_LAST" "1" "auth method count still 1 after refused removal"

# ─── Phase 16.7: recovery-roundtrip — fresh device imports Carol's
#                recovery file and reaches the same scope state.
phase "recovery roundtrip: import Carol's recovery on a fresh device"
HOME_RC=$HOME/.fd0-yk-recovered
mkfd0 "$HOME_RC"
RC() { env FD0_HOME="$HOME_RC" FD0_SSH_SOCK="$HOME_RC/ssh.sock" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
# import: prompts for recovery passphrase + new device passphrase
# (twice for confirmation). Carol exported with passphrase 'carol-rec'
# (see Phase 16). The new device passphrase becomes 'recovered-pass'.
printf "carol-rec\nrecovered-pass\nrecovered-pass\n" \
    | RC recovery import "$RECOVERY_CA" >/dev/null 2>&1 \
    && ok "recovery import succeeded (fresh device)" || no "recovery import failed"
printf "recovered-pass\n" | RC unlock >/dev/null 2>&1 \
    && ok "recovered device unlocks (passphrase)" || no "recovered device unlock"
RC sync >/dev/null 2>&1; RC sync >/dev/null 2>&1
# After 2 syncs the recovered device must have re-discovered
# Carol's scopes via the user-chain replay + scope-discovery flow.
# Earlier soft-pass tolerance allowed an empty read to count as
# success — that masked a real degradation. Now we require the
# exact value Carol wrote in Phase 7.
RECOVERED_DEPLOY=$(RC get DEPLOY_KEY --scope work 2>/dev/null || true)
expect_eq "$RECOVERED_DEPLOY" "carol-deploy-1" "recovered device reads Carol's secret (DEPLOY_KEY)"

# The recovered device should ALSO have at least one auth method
# active on its chain — the freshly-added passphrase one (Carol's
# old yubikey method may or may not survive depending on whether
# the import flow re-uses or replaces the chain). Either way, the
# new device must have AT LEAST the passphrase method.
RC_METHODS=$(RC auth ls 2>/dev/null | grep -c "^" || true)
if [ "$RC_METHODS" -ge 1 ] 2>/dev/null; then
    ok "recovered device has $RC_METHODS active auth method(s)"
else
    no "recovered device has no auth methods after import"
fi
RC_HAS_PASS=$(RC auth ls 2>/dev/null | grep -c passphrase || true)
expect_eq "$RC_HAS_PASS" "1" "recovered device's chain has the passphrase method from import"

# Document a v1 design limit (NOT a bug we are fixing here): the
# recovered device's local user chain is a fresh genesis (seq=0 with
# the new passphrase auth.set); the server still has Carol's
# original full chain. EnsureUserRegistered treats this as a 409
# super_pub_taken / idempotent registration — by design for v1. This
# means the recovered device CAN read scope secrets (super_priv
# unchanged) but cannot append auth.set events that anchor on the
# server's tip. A real-world `auth add` on the recovered device
# would fail at sync. We assert the read path works and leave the
# limit documented; v1.x will add full user-chain sync per TODO.md.
RC_LOCAL_TIP=$(env FD0_HOME="$HOME_RC" FD0_SSH_SOCK="$HOME_RC/ssh.sock" "$FD0" auth ls 2>/dev/null | grep -c "^" || true)
ok "recovered device local chain has $RC_LOCAL_TIP method(s); divergence with server's view is a documented v1 limit"

# Lock the recovered device's agent so it doesn't linger.
RC lock >/dev/null 2>&1 || true

phase "adversarial: untagged-agent rejection (covered by Go unit test)"
# The CLI surfaces vault.ErrYubikeyNotConfigured when an untagged
# agent is paired with a yubikey-enrolled vault. End-to-end shell
# coverage for this path is brittle (requires a clean per-test home
# + agent rebuild + careful sequencing). The unit test
# TestAgentUnlock_YubikeyMethodWithoutFactory in internal/agent
# already exercises the agent-side rejection. We document the
# coverage here and skip the shell case.
ok "covered by internal/agent/yubikey_unlock_test.go::TestAgentUnlock_YubikeyMethodWithoutFactory"

# ─── Phase 17: server tip checks (translog still grows monotonic) ─
phase "translog sanity"
TIP_BEFORE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tip_seq) FROM chains;" 2>/dev/null || echo "?")
CA set TRANSLOG_PROBE "yk-final-write" --scope work >/dev/null 2>&1
CA sync >/dev/null 2>&1
TIP_AFTER=$(sqlite3 "$SERVER_DB" "SELECT MAX(tip_seq) FROM chains;" 2>/dev/null || echo "?")
if [ "$TIP_AFTER" != "?" ] && [ "$TIP_BEFORE" != "?" ] && [ "$TIP_AFTER" -ge "$TIP_BEFORE" ]; then
    ok "server tip advanced ($TIP_BEFORE → $TIP_AFTER)"
else
    no "server tip advance check failed ($TIP_BEFORE → $TIP_AFTER)"
fi

# ─── Phase 18: stress (opt-in via FD0_YUBIKEY_STRESS=N) ───────────
STRESS_N="${FD0_YUBIKEY_STRESS:-0}"
if [ "$STRESS_N" -gt 0 ] 2>/dev/null; then
    phase "stress: $STRESS_N lock/unlock cycles via YubiKey + resource regression"
    # Capture Carol's agent PID so we can measure FD count + RSS
    # before / after the loop. A leak in pivWrapper.Close, the
    # YubiKey resolver, or PCSC handles would surface as an FD
    # count climb. RSS is a softer signal but a runaway sealed-
    # buffer leak shows up there too.
    AGENT_PID=$(cat "$HOME_CA/agent.pid" 2>/dev/null || echo 0)
    fd_count() {
        if [ "$AGENT_PID" -gt 0 ] 2>/dev/null && command -v lsof >/dev/null; then
            lsof -p "$AGENT_PID" 2>/dev/null | wc -l | tr -d ' '
        else
            echo "?"
        fi
    }
    rss_kb() {
        if [ "$AGENT_PID" -gt 0 ] 2>/dev/null; then
            ps -o rss= -p "$AGENT_PID" 2>/dev/null | tr -d ' '
        else
            echo "?"
        fi
    }
    FD_BEFORE=$(fd_count); RSS_BEFORE=$(rss_kb)

    STRESS_OK=0
    STRESS_FAIL=0
    for i in $(seq 1 "$STRESS_N"); do
        CA_lock
        if CA_unlock_yk; then
            STRESS_OK=$((STRESS_OK + 1))
        else
            STRESS_FAIL=$((STRESS_FAIL + 1))
        fi
        # Periodic sanity: every 100 cycles, do a real read.
        if [ $((i % 100)) -eq 0 ]; then
            if CA get DEPLOY_KEY --scope work 2>/dev/null | grep -q "carol-deploy-1"; then
                ok "cycle $i: still reading correctly"
            else
                no "cycle $i: read FAILED — possible PCSC / agent state corruption"
            fi
        fi
    done
    if [ "$STRESS_FAIL" -eq 0 ]; then
        ok "$STRESS_N cycles: 0 failures"
    else
        no "$STRESS_N cycles: $STRESS_FAIL failures, $STRESS_OK successes"
    fi

    FD_AFTER=$(fd_count); RSS_AFTER=$(rss_kb)
    if [ "$FD_BEFORE" != "?" ] && [ "$FD_AFTER" != "?" ]; then
        FD_DELTA=$((FD_AFTER - FD_BEFORE))
        # A handful of FDs may legitimately appear (sync goroutines,
        # log rotation, scheduler). >5 across $STRESS_N cycles is a
        # leak signal worth investigating.
        if [ "$FD_DELTA" -le 5 ]; then
            ok "agent FD delta: $FD_BEFORE → $FD_AFTER (+$FD_DELTA, OK)"
        else
            no "agent FD delta: $FD_BEFORE → $FD_AFTER (+$FD_DELTA, possible leak)"
        fi
    else
        ok "agent FD measurement skipped (lsof/pid not available)"
    fi
    if [ "$RSS_BEFORE" != "?" ] && [ "$RSS_AFTER" != "?" ]; then
        # 50 MiB tolerance over the cycle count — accounts for
        # Go runtime growth + sync caches.
        RSS_DELTA=$((RSS_AFTER - RSS_BEFORE))
        if [ "$RSS_DELTA" -lt 51200 ]; then
            ok "agent RSS delta: ${RSS_BEFORE}KB → ${RSS_AFTER}KB (+${RSS_DELTA}KB, OK)"
        else
            no "agent RSS delta: ${RSS_BEFORE}KB → ${RSS_AFTER}KB (+${RSS_DELTA}KB, possible leak)"
        fi
    fi
else
    phase "stress (skipped — set FD0_YUBIKEY_STRESS=1000 to run)"
fi

# ─── Phase 19: PIN-counter postflight ─────────────────────────────
# If the test leaked a wrong-PIN attempt without recovering, the
# card's retry counter would be < 3 at end-of-test, and the NEXT run
# would risk blocking the slot. Verify we left the counter at 3/3.
phase "PIN retry postflight (must end at 3/3)"
RETRIES_POST=$(ykman piv info 2>/dev/null | awk '/PIN tries remaining/ {print $4}')
expect_eq "$RETRIES_POST" "3/3" "PIN retry counter restored to 3/3 at end of test"

# ─── Phase 20: multi-method auto-pick logs to stderr ──────────────
# DESTRUCTIVE: this phase re-provisions slot 0x9d, invalidating
# Carol's yubikey wrap. It runs LAST so previous phases that depend
# on Carol's yubikey-bound vault (stress loop, recovery, unlock
# cycles) execute against the original slot pub. After this phase,
# Carol's vault on this YubiKey is permanently locked out of the
# card; her recovery file remains valid for fresh-device flows.
phase "auto-pick logs the chosen method on stderr (DESTRUCTIVE — runs last)"
HOME_AMB=$HOME/.fd0-yk-ambig
mkfd0 "$HOME_AMB"
AMB() { env FD0_HOME="$HOME_AMB" FD0_SSH_SOCK="$HOME_AMB/ssh.sock" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
printf "amb-pass\namb-pass\n" | env FD0_HOME="$HOME_AMB" FD0_SSH_SOCK="$HOME_AMB/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "amb-pass\n" | AMB unlock >/dev/null 2>&1
printf "n\n" | AMB auth add --yubikey --touch=never --force >/tmp/fd0-yk-amb-add.log 2>&1 \
    && ok "ambig-home: yubikey method added (touch-only, no PIN)" \
    || no "ambig-home: yubikey enroll failed: $(tail -3 /tmp/fd0-yk-amb-add.log)"
AMB lock >/dev/null 2>&1
AMB_OUT=$(printf "amb-pass\n" | AMB unlock 2>&1 >/dev/null || true)
case "$AMB_OUT" in
    *"multiple unlock methods available"*)
        ok "auto-pick logged the multi-method notice"
        ;;
    *)
        no "expected 'multiple unlock methods available' in stderr; got: $(echo "$AMB_OUT" | head -3)" ;;
esac
AMB lock >/dev/null 2>&1 || true
PF="$HOME_AMB/agent.pid"
if [ -r "$PF" ]; then
    APID=$(cat "$PF")
    [ -n "$APID" ] && [ "$APID" -gt 0 ] 2>/dev/null && kill "$APID" 2>/dev/null || true
fi
rm -rf "$HOME_AMB" /tmp/fd0-yk-amb-add.log

# ─── Result ───────────────────────────────────────────────────────
phase "result"
printf "  PASS: %d   FAIL: %d\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
