#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE=$(mktemp -d "${TMPDIR:-/tmp}/fd0-desktop-installer.XXXXXX")
trap 'rm -rf "$BASE"' EXIT

RELEASE="$BASE/releases/download/desktop-v0.1.0"
FAKE_BIN="$BASE/bin"
mkdir -p "$RELEASE" "$FAKE_BIN"

printf 'mac artifact\n' > "$RELEASE/fd0-desktop_0.1.0_mac_arm64.dmg"
cat > "$RELEASE/fd0-desktop_0.1.0_linux_arm64.AppImage" <<'EOF'
#!/bin/sh
case "$1" in
  --fd0-cli-relay)
    shift
    if [ "${1:-}" = version ]; then
      printf 'fd0 0.1.0 standard\n'
    else
      printf 'linux fd0 %s managed=%s\n' "$*" "${FD0_DESKTOP_MANAGED:-relay}"
    fi
    ;;
  --fd0-agent-relay) shift; printf 'linux agent %s\n' "$*" ;;
  --fd0-browser-host-relay) shift; printf 'linux browser host %s\n' "$*" ;;
  *) printf 'desktop app\n' ;;
esac
EOF
chmod +x "$RELEASE/fd0-desktop_0.1.0_linux_arm64.AppImage"
cp "$RELEASE/fd0-desktop_0.1.0_linux_arm64.AppImage" \
  "$RELEASE/fd0-desktop_0.1.0_linux_x86_64.AppImage"
printf 'fd0 icon\n' > "$RELEASE/sh.fd0.desktop.png"
(
  cd "$RELEASE"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum fd0-desktop_* sh.fd0.desktop.png
  else
    shasum -a 256 fd0-desktop_* sh.fd0.desktop.png | awk '{print $1 "  " $2}'
  fi
) > "$RELEASE/checksums.txt"
printf 'desktop-v0.1.0\n' > "$RELEASE/checksums.txt.sigstore.json"

OLD_DESKTOP_RELEASE="$BASE/releases/download/desktop-v0.0.9"
mkdir -p "$OLD_DESKTOP_RELEASE"
cat > "$OLD_DESKTOP_RELEASE/fd0-desktop_0.0.9_linux_arm64.AppImage" <<'EOF'
#!/bin/sh
if [ "$1" = "--fd0-cli-relay" ] && [ "${2:-}" = version ]; then
  printf 'fd0 0.0.9 standard\n'
fi
EOF
chmod +x "$OLD_DESKTOP_RELEASE/fd0-desktop_0.0.9_linux_arm64.AppImage"
(
  cd "$OLD_DESKTOP_RELEASE"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum fd0-desktop_*
  else
    shasum -a 256 fd0-desktop_* | awk '{print $1 "  " $2}'
  fi
) > "$OLD_DESKTOP_RELEASE/checksums.txt"
printf 'desktop-v0.0.9\n' > "$OLD_DESKTOP_RELEASE/checksums.txt.sigstore.json"

make_client_release() {
  version=$1
  release="$BASE/releases/download/v$version"
  staging="$BASE/client-$version"
  yubikey_staging="$BASE/client-$version-yubikey"
  mkdir -p "$release" "$staging" "$yubikey_staging"
  cat > "$staging/fd0" <<EOF
#!/bin/sh
if [ "\${1:-}" = version ]; then printf 'fd0 $version standard\\n'; fi
EOF
  cat > "$staging/fd0-agent" <<EOF
#!/bin/sh
printf 'fd0-agent $version\\n'
EOF
  cat > "$staging/fd0-browser-host" <<EOF
#!/bin/sh
printf 'fd0-browser-host $version\\n'
EOF
  chmod +x "$staging/fd0" "$staging/fd0-agent" "$staging/fd0-browser-host"
  cat > "$yubikey_staging/fd0" <<EOF
#!/bin/sh
if [ "\${1:-}" = version ]; then printf 'fd0 $version yubikey\\n'; fi
EOF
  cat > "$yubikey_staging/fd0-agent" <<EOF
#!/bin/sh
printf 'fd0-agent $version yubikey\\n'
EOF
  cat > "$yubikey_staging/fd0-browser-host" <<EOF
#!/bin/sh
printf 'fd0-browser-host $version yubikey\\n'
EOF
  chmod +x "$yubikey_staging/fd0" "$yubikey_staging/fd0-agent" "$yubikey_staging/fd0-browser-host"
  if [ "$version" = 0.0.9 ]; then
    tar -czf "$release/fd0_linux_arm64.tar.gz" -C "$staging" fd0 fd0-agent
    tar -czf "$release/fd0_yubikey_linux_arm64.tar.gz" -C "$yubikey_staging" fd0 fd0-agent
  else
    tar -czf "$release/fd0_linux_arm64.tar.gz" -C "$staging" fd0 fd0-agent fd0-browser-host
    tar -czf "$release/fd0_yubikey_linux_arm64.tar.gz" -C "$yubikey_staging" fd0 fd0-agent fd0-browser-host
  fi
  (
    cd "$release"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum fd0_linux_arm64.tar.gz fd0_yubikey_linux_arm64.tar.gz
    else
      shasum -a 256 fd0_linux_arm64.tar.gz fd0_yubikey_linux_arm64.tar.gz | awk '{print $1 "  " $2}'
    fi
  ) > "$release/checksums.txt"
  printf 'client-v%s\n' "$version" > "$release/checksums.txt.sigstore.json"
}
make_client_release 0.1.0
make_client_release 0.0.9

make_traversal_client_release() {
  version=0.1.1
  release="$BASE/releases/download/v$version"
  staging="$BASE/client-$version"
  mkdir -p "$release" "$staging"
  cat > "$staging/fd0" <<'EOF'
#!/bin/sh
if [ "${1:-}" = version ]; then printf 'fd0 0.1.1 standard\n'; fi
EOF
  cat > "$staging/fd0-agent" <<'EOF'
#!/bin/sh
printf 'fd0-agent 0.1.1\n'
EOF
  cat > "$staging/fd0-browser-host" <<'EOF'
#!/bin/sh
printf 'fd0-browser-host 0.1.1\n'
EOF
  printf 'must not escape\n' > "$staging/archive-escape-marker"
  chmod +x "$staging/fd0" "$staging/fd0-agent" "$staging/fd0-browser-host"
  if tar --version 2>/dev/null | grep -q GNU; then
    tar -czf "$release/fd0_linux_arm64.tar.gz" \
      --transform='s,^archive-escape-marker$,../../archive-escape-marker,' \
      -C "$staging" fd0 fd0-agent fd0-browser-host archive-escape-marker
  else
    tar -czf "$release/fd0_linux_arm64.tar.gz" \
      -s ',^archive-escape-marker$,../../archive-escape-marker,' \
      -C "$staging" fd0 fd0-agent fd0-browser-host archive-escape-marker
  fi
  (
    cd "$release"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum fd0_linux_arm64.tar.gz
    else
      shasum -a 256 fd0_linux_arm64.tar.gz | awk '{print $1 "  " $2}'
    fi
  ) > "$release/checksums.txt"
  printf 'client-v%s\n' "$version" > "$release/checksums.txt.sigstore.json"
}
make_traversal_client_release

mkdir -p "$BASE/api"
cat > "$BASE/api/releases" <<'EOF'
[
  {
    "tag_name": "v0.0.9",
    "name": "client-v0.0.9"
  },
  {
    "tag_name": "desktop-v0.2.0",
    "name": "Desktop 0.2.0 — free-form title"
  },
  {
    "tag_name": "v0.1.0",
    "name": "CLI 0.1.0 — free-form title"
  }
]
EOF
cat > "$BASE/desktop-feed" <<'EOF'
desktop-v0.0.9
desktop-v0.1.0
EOF

cat > "$FAKE_BIN/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "${TEST_UNAME_S:?}" ;;
  -m) printf '%s\n' "${TEST_UNAME_M:?}" ;;
  *) exit 2 ;;
esac
EOF

cat > "$FAKE_BIN/hdiutil" <<'EOF'
#!/bin/sh
if [ "$1" = "detach" ]; then exit 0; fi
mount=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-mountpoint" ]; then mount=$2; shift 2; else shift; fi
done
test -n "$mount"
mkdir -p "$mount/fd0.app/Contents/Resources/bin"
printf 'desktop app\n' > "$mount/fd0.app/Contents/version"
cat > "$mount/fd0.app/Contents/Resources/bin/fd0" <<'EOS'
#!/bin/sh
printf 'mac fd0 %s managed=%s\n' "$*" "${FD0_DESKTOP_MANAGED:-}"
EOS
cat > "$mount/fd0.app/Contents/Resources/bin/fd0-agent" <<'EOS'
#!/bin/sh
printf 'mac agent %s\n' "$*"
EOS
chmod +x "$mount/fd0.app/Contents/Resources/bin/fd0" "$mount/fd0.app/Contents/Resources/bin/fd0-agent"
EOF

cat > "$FAKE_BIN/ditto" <<'EOF'
#!/bin/sh
cp -R "$1" "$2"
EOF
cat > "$FAKE_BIN/codesign" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$FAKE_BIN/spctl" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$FAKE_BIN/cosign" <<'EOF'
#!/bin/sh
[ "${TEST_COSIGN_REJECT:-0}" != "1" ] || exit 1
certificate=""
identity=""
while [ $# -gt 0 ]; do
  case "$1" in
    --certificate) certificate=$2; shift 2 ;;
    --bundle) certificate=$2; shift 2 ;;
    --certificate-identity-regexp) identity=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$certificate" ] && [ -n "$identity" ] || exit 9
tag=$(cat "$certificate")
escaped_tag=$(printf '%s' "$tag" | sed 's/\./\\./g')
case "$tag" in
  desktop-v*) workflow=release-desktop ;;
  client-v*|fd0-v*) workflow=release ;;
  *) exit 9 ;;
esac
expected="^https://github\\.com/k2b-dev/fd0\\.sh/\\.github/workflows/${workflow}\\.yml@refs/tags/${escaped_tag}$"
[ "$identity" = "$expected" ] || exit 9
EOF
chmod +x "$FAKE_BIN/uname" "$FAKE_BIN/hdiutil" "$FAKE_BIN/ditto" "$FAKE_BIN/codesign" "$FAKE_BIN/spctl" "$FAKE_BIN/cosign"

run_installer() {
  HOME=$1 \
  TEST_UNAME_S=$2 \
  TEST_UNAME_M=${3:-arm64} \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_DESKTOP_VERSION=desktop-v0.1.0 \
  FD0_DESKTOP_ASSUME_YES=1 \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    sh "$ROOT/scripts/install-desktop.sh"
}

run_interactive() {
  local answers=$1
  shift
  INTERACTIVE_ANSWERS="$answers" python3 - "$@" <<'PY'
import errno
import os
import pty
import sys

answers = os.environ.pop("INTERACTIVE_ANSWERS").encode()
pid, master = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])

os.write(master, answers)
output = bytearray()
while True:
    try:
        chunk = os.read(master, 4096)
    except OSError as error:
        if error.errno == errno.EIO:
            break
        raise
    if not chunk:
        break
    output.extend(chunk)

_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(output)
raise SystemExit(os.waitstatus_to_exitcode(status))
PY
}

MAC_HOME="$BASE/mac-home"
run_installer "$MAC_HOME" Darwin >/dev/null
test "$(cat "$MAC_HOME/Applications/fd0.app/Contents/version")" = "desktop app"
test "$(HOME="$MAC_HOME" "$MAC_HOME/.local/bin/fd0" version)" = "mac fd0 version managed=1"
test "$(HOME="$MAC_HOME" "$MAC_HOME/.local/bin/fd0-agent" check)" = "mac agent check"

LINUX_HOME="$BASE/linux-home"
LINUX_INSTALL_OUTPUT=$(run_installer "$LINUX_HOME" Linux 2>&1)
test -x "$LINUX_HOME/.local/bin/fd0-desktop"
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0-agent" check)" = "linux agent check"
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0-browser-host" chrome-extension://test/)" = \
  "linux browser host chrome-extension://test/"
test -x "$LINUX_HOME/.local/bin/fd0-browser-host"
grep -Fq "Exec=$LINUX_HOME/.local/bin/fd0-desktop" \
  "$LINUX_HOME/.local/share/applications/sh.fd0.desktop.desktop"
grep -Fq "Icon=sh.fd0.desktop" \
  "$LINUX_HOME/.local/share/applications/sh.fd0.desktop.desktop"
test "$(cat "$LINUX_HOME/.local/share/icons/hicolor/512x512/apps/sh.fd0.desktop.png")" = "fd0 icon"
printf '%s\n' "$LINUX_INSTALL_OUTPUT" | grep -Fq "… Downloading fd0 Desktop"
printf '%s\n' "$LINUX_INSTALL_OUTPUT" | grep -Fq "✓ Authenticating signed release"
printf '%s\n' "$LINUX_INSTALL_OUTPUT" | grep -Fq "✓ Chrome browser integration enabled"
printf '%s\n' "$LINUX_INSTALL_OUTPUT" | grep -Fq "Next steps:"
printf '%s\n' "$LINUX_INSTALL_OUTPUT" | grep -Fq "\"$LINUX_HOME/.local/bin/fd0-desktop\""
printf '%s\n' "$LINUX_INSTALL_OUTPUT" | grep -Fq "fd0 doctor"

LINUX_X64_HOME="$BASE/linux-x64-home"
run_installer "$LINUX_X64_HOME" Linux x86_64 >/dev/null
test "$(HOME="$LINUX_X64_HOME" "$LINUX_X64_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"

run_installer "$LINUX_HOME" Linux >/dev/null
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"

LATEST_DESKTOP_HOME="$BASE/latest-desktop-home"
HOME="$LATEST_DESKTOP_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_DESKTOP_FEED_URL="file://$BASE/desktop-feed" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_DESKTOP_ASSUME_YES=1 \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install-desktop.sh" >/dev/null
test "$(HOME="$LATEST_DESKTOP_HOME" "$LATEST_DESKTOP_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"

if HOME="$LINUX_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_DESKTOP_VERSION=desktop-v0.0.9 \
  FD0_DESKTOP_ASSUME_YES=1 \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    sh "$ROOT/scripts/install-desktop.sh" >/dev/null 2>&1; then
  echo "desktop installer accepted a downgrade without explicit authorization" >&2
  exit 1
fi
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"

MAIN_HOME="$BASE/main-installer-home"
HOME="$MAIN_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_DESKTOP_INSTALL_URL="file://$ROOT/scripts/install-desktop.sh" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install.sh" --desktop --version=0.1.0 --yes >/dev/null
test "$(HOME="$MAIN_HOME" "$MAIN_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"

INTERACTIVE_DESKTOP_HOME="$BASE/interactive-desktop-home"
INTERACTIVE_DESKTOP_OUTPUT=$(HOME="$INTERACTIVE_DESKTOP_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_DESKTOP_INSTALL_URL="file://$ROOT/scripts/install-desktop.sh" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    run_interactive $'\n\n' sh "$ROOT/scripts/install.sh" --version=0.1.0)
printf '%s\n' "$INTERACTIVE_DESKTOP_OUTPUT" | grep -Fq "What would you like to install?"
printf '%s\n' "$INTERACTIVE_DESKTOP_OUTPUT" | grep -Fq "Select [1]:"
test "$(HOME="$INTERACTIVE_DESKTOP_HOME" "$INTERACTIVE_DESKTOP_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"

INTERACTIVE_YUBIKEY_HOME="$BASE/interactive-yubikey-home"
INTERACTIVE_YUBIKEY_PREFIX="$INTERACTIVE_YUBIKEY_HOME/bin"
INTERACTIVE_YUBIKEY_OUTPUT=$(HOME="$INTERACTIVE_YUBIKEY_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    run_interactive $'2\ny\n\n' sh "$ROOT/scripts/install.sh" \
      --prefix="$INTERACTIVE_YUBIKEY_PREFIX" --version=0.1.0)
printf '%s\n' "$INTERACTIVE_YUBIKEY_OUTPUT" | grep -Fq "Include YubiKey support? [y/N]"
test "$("$INTERACTIVE_YUBIKEY_PREFIX/fd0" version)" = "fd0 0.1.0 yubikey"

INTERACTIVE_UPDATE_HOME="$BASE/interactive-update-home"
INTERACTIVE_UPDATE_PREFIX="$INTERACTIVE_UPDATE_HOME/bin"
HOME="$INTERACTIVE_UPDATE_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install.sh" --prefix="$INTERACTIVE_UPDATE_PREFIX" \
    --version=0.0.9 --yubikey --yes >/dev/null
if HOME="$INTERACTIVE_UPDATE_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    run_interactive $'\n\nn\n' sh "$ROOT/scripts/install.sh" \
      --prefix="$INTERACTIVE_UPDATE_PREFIX" --version=0.1.0 >"$BASE/rejected-update-output"; then
  echo "interactive client update ignored a rejected confirmation" >&2
  exit 1
fi
grep -Fq "Select [2]:" "$BASE/rejected-update-output"
grep -Fq "Include YubiKey support? [Y/n]" "$BASE/rejected-update-output"
grep -Fq "proceed with upgrade? [Y/n]" "$BASE/rejected-update-output"
test "$("$INTERACTIVE_UPDATE_PREFIX/fd0" version)" = "fd0 0.0.9 yubikey"

HOME="$INTERACTIVE_UPDATE_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  run_interactive $'\n\n\n' sh "$ROOT/scripts/install.sh" \
    --prefix="$INTERACTIVE_UPDATE_PREFIX" --version=0.1.0 >/dev/null
test "$("$INTERACTIVE_UPDATE_PREFIX/fd0" version)" = "fd0 0.1.0 yubikey"

CLIENT_HOME="$BASE/client-home"
CLIENT_PREFIX="$CLIENT_HOME/bin"
NONINTERACTIVE_OUTPUT=$(HOME="$CLIENT_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install.sh" --prefix="$CLIENT_PREFIX" --version=0.1.0 --yes)
if printf '%s\n' "$NONINTERACTIVE_OUTPUT" | grep -Fq "What would you like to install?"; then
  echo "--yes unexpectedly opened the product selection prompt" >&2
  exit 1
fi
test "$("$CLIENT_PREFIX/fd0" version)" = "fd0 0.1.0 standard"
test "$("$CLIENT_PREFIX/fd0-browser-host")" = "fd0-browser-host 0.1.0"
printf '%s\n' "$NONINTERACTIVE_OUTPUT" | grep -Fq "✓ Chrome browser integration enabled"

LATEST_HOME="$BASE/latest-client-home"
HOME="$LATEST_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_API_BASE="file://$BASE/api" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install.sh" --prefix="$LATEST_HOME/bin" --yes >/dev/null
test "$("$LATEST_HOME/bin/fd0" version)" = "fd0 0.1.0 standard"

TRAVERSAL_HOME="$BASE/traversal-client-home"
HOME="$TRAVERSAL_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install.sh" --prefix="$TRAVERSAL_HOME/bin" --version=0.1.1 --yes >/dev/null
test "$("$TRAVERSAL_HOME/bin/fd0" version)" = "fd0 0.1.1 standard"
test ! -e "$FD0_TEST_ROOT/archive-escape-marker"

if HOME="$CLIENT_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    sh "$ROOT/scripts/install.sh" --prefix="$CLIENT_PREFIX" --version=0.0.9 --yes >/dev/null 2>&1; then
  echo "client installer accepted a downgrade without explicit authorization" >&2
  exit 1
fi
test "$("$CLIENT_PREFIX/fd0" version)" = "fd0 0.1.0 standard"

HOME="$CLIENT_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install.sh" --prefix="$CLIENT_PREFIX" --version=0.0.9 --allow-downgrade --yes >/dev/null
test "$("$CLIENT_PREFIX/fd0" version)" = "fd0 0.0.9 standard"
test ! -e "$CLIENT_PREFIX/fd0-browser-host"

FRESH_OLD_HOME="$BASE/fresh-old-home"
FRESH_OLD_PREFIX="$FRESH_OLD_HOME/bin"
mkdir -p "$FRESH_OLD_PREFIX"
cat > "$FRESH_OLD_PREFIX/fd0-browser-host" <<'EOF'
#!/bin/sh
printf 'foreign browser host\n'
EOF
chmod +x "$FRESH_OLD_PREFIX/fd0-browser-host"
HOME="$FRESH_OLD_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
  sh "$ROOT/scripts/install.sh" --prefix="$FRESH_OLD_PREFIX" \
    --version=0.0.9 --yes >/dev/null
test "$("$FRESH_OLD_PREFIX/fd0-browser-host")" = "foreign browser host"

REJECTED_CLIENT_HOME="$BASE/rejected-client-home"
if HOME="$REJECTED_CLIENT_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  TEST_COSIGN_REJECT=1 \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    sh "$ROOT/scripts/install.sh" --prefix="$REJECTED_CLIENT_HOME/bin" --version=0.1.0 --yes >/dev/null 2>&1; then
  echo "client installer accepted a rejected publisher signature" >&2
  exit 1
fi
test ! -e "$REJECTED_CLIENT_HOME/bin/fd0"

mkdir -p "$MAIN_HOME/.fd0"
printf 'keep\n' > "$MAIN_HOME/.fd0/vault.enc"
HOME="$MAIN_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_DESKTOP_ASSUME_YES=1 \
  sh "$ROOT/scripts/install-desktop.sh" --uninstall --yes >/dev/null
test ! -e "$MAIN_HOME/.local/bin/fd0-desktop"
test ! -e "$MAIN_HOME/.local/bin/fd0"
test ! -e "$MAIN_HOME/.local/bin/fd0-agent"
test ! -e "$MAIN_HOME/.local/bin/fd0-browser-host"
test ! -e "$MAIN_HOME/.local/share/applications/sh.fd0.desktop.desktop"
test ! -e "$MAIN_HOME/.local/share/icons/hicolor/512x512/apps/sh.fd0.desktop.png"
test "$(cat "$MAIN_HOME/.fd0/vault.enc")" = "keep"

OWNED_HOME="$BASE/owned-home"
mkdir -p "$OWNED_HOME/.local/bin" "$OWNED_HOME/.fd0"
cat > "$OWNED_HOME/.local/bin/fd0" <<'EOF'
#!/bin/sh
printf 'standalone fd0\n'
EOF
cat > "$OWNED_HOME/.local/bin/fd0-agent" <<'EOF'
#!/bin/sh
printf 'standalone agent\n'
EOF
cat > "$OWNED_HOME/.local/bin/fd0-browser-host" <<'EOF'
#!/bin/sh
printf 'standalone browser host\n'
EOF
chmod +x "$OWNED_HOME/.local/bin/fd0" "$OWNED_HOME/.local/bin/fd0-agent" \
  "$OWNED_HOME/.local/bin/fd0-browser-host"
printf 'keep owned vault\n' > "$OWNED_HOME/.fd0/vault.enc"
run_installer "$OWNED_HOME" Linux >/dev/null
test "$(HOME="$OWNED_HOME" "$OWNED_HOME/.local/bin/fd0" version)" = "fd0 0.1.0 standard"
HOME="$OWNED_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_DESKTOP_ASSUME_YES=1 \
  sh "$ROOT/scripts/install-desktop.sh" --uninstall --yes >/dev/null
test "$(HOME="$OWNED_HOME" "$OWNED_HOME/.local/bin/fd0")" = "standalone fd0"
test "$(HOME="$OWNED_HOME" "$OWNED_HOME/.local/bin/fd0-agent")" = "standalone agent"
test "$(HOME="$OWNED_HOME" "$OWNED_HOME/.local/bin/fd0-browser-host")" = \
  "standalone browser host"
test "$(cat "$OWNED_HOME/.fd0/vault.enc")" = "keep owned vault"

printf 'tampered\n' >> "$RELEASE/fd0-desktop_0.1.0_linux_arm64.AppImage"
TAMPERED_HOME="$BASE/tampered-home"
if run_installer "$TAMPERED_HOME" Linux >/dev/null 2>&1; then
  echo "desktop installer accepted a checksum mismatch" >&2
  exit 1
fi
test ! -e "$TAMPERED_HOME/.local/bin/fd0-desktop"

if HOME="$BASE/invalid-home" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_DESKTOP_VERSION='desktop-v../../escape' \
  FD0_DESKTOP_ASSUME_YES=1 \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    sh "$ROOT/scripts/install-desktop.sh" >/dev/null 2>&1; then
  echo "desktop installer accepted an invalid release tag" >&2
  exit 1
fi

MISSING_COSIGN_HOME="$BASE/missing-cosign-home"
if HOME="$MISSING_COSIGN_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_DESKTOP_VERSION=desktop-v0.1.0 \
  FD0_DESKTOP_ASSUME_YES=1 \
  FD0_COSIGN_BIN="$BASE/missing-cosign" \
    sh "$ROOT/scripts/install-desktop.sh" >/dev/null 2>&1; then
  echo "desktop installer accepted an unauthenticated release without cosign" >&2
  exit 1
fi
test ! -e "$MISSING_COSIGN_HOME/.local/bin/fd0-desktop"

REJECTED_HOME="$BASE/rejected-signature-home"
if HOME="$REJECTED_HOME" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  TEST_COSIGN_REJECT=1 \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_DESKTOP_VERSION=desktop-v0.1.0 \
  FD0_DESKTOP_ASSUME_YES=1 \
  FD0_COSIGN_BIN="$FAKE_BIN/cosign" \
    sh "$ROOT/scripts/install-desktop.sh" >/dev/null 2>&1; then
  echo "desktop installer accepted a rejected publisher signature" >&2
  exit 1
fi
test ! -e "$REJECTED_HOME/.local/bin/fd0-desktop"

echo "ok desktop installer"
