#!/bin/sh
# fd0 — client installer / updater (workstation, laptop).
#
#   curl -fsSL https://fd0.sh/install | sh
#   curl -fsSL https://fd0.sh/install | sh -s -- --yubikey
#   curl -fsSL https://fd0.sh/install | sh -s -- --desktop
#   curl -fsSL https://fd0.sh/install | sh -s -- --system
#   FD0_VERSION=v1.0.0 curl -fsSL https://fd0.sh/install | sh
#
# Supported platforms:
#   - linux  / amd64, arm64
#   - darwin / amd64, arm64   (macOS Intel + Apple Silicon)
#
# Windows: not yet built by the release pipeline. The fd0 client is
# pure Go and would cross-compile, but the AF_UNIX agent socket and
# %LOCALAPPDATA% path conventions have not been validated. Track at
# https://github.com/k2b-dev/fd0.sh/issues.
#
# Installs `fd0`, `fd0-agent`, and `fd0-browser-host` into ~/.local/bin (default) or
# /usr/local/bin (--system), seeds ~/.fd0/config.toml if absent,
# and prints a PATH hint when ~/.local/bin isn't on $PATH. Without an
# explicit product or flavor, interactive runs offer Desktop or CLI.
#
# Doubles as an upgrade script: detects an existing install, prints
# `current → new`, and asks before touching anything. Verifies the
# release checksum manifest against the published cosign signature.
#
# For server-side deployments (fd0-server, fd0-witness) use the
# Docker compose blocks in deploy/ — see docs/HOSTING.md for the
# full production recipe.

set -eu

# ─── defaults ────────────────────────────────────────────────────────────
REPO="k2b-dev/fd0.sh"
RELEASE_BASE="${FD0_RELEASE_BASE:-https://github.com/${REPO}/releases}"
API_BASE="${FD0_API_BASE:-https://api.github.com/repos/${REPO}}"
PREFIX="${HOME}/.local/bin"
SYSTEM=0
VERSION="${FD0_VERSION:-latest}"
ASSUME_YES=0
ALLOW_DOWNGRADE=0
REQUIRED_BINARIES="fd0 fd0-agent"
OPTIONAL_BINARIES="fd0-browser-host"
FLAVOR_EXPLICIT=0
if [ "${FD0_FLAVOR+x}" = x ]; then
    FLAVOR_EXPLICIT=1
fi
FLAVOR="${FD0_FLAVOR:-auto}"
DESKTOP=0
CUSTOM_PREFIX=0

while [ $# -gt 0 ]; do
    case "$1" in
        --system)       SYSTEM=1; PREFIX="/usr/local/bin"; shift ;;
        --prefix=*)     PREFIX="${1#--prefix=}"; CUSTOM_PREFIX=1; shift ;;
        --version=*)    VERSION="${1#--version=}"; shift ;;
        --flavor=*)     FLAVOR="${1#--flavor=}"; FLAVOR_EXPLICIT=1; shift ;;
        --yubikey)      FLAVOR="yubikey"; FLAVOR_EXPLICIT=1; shift ;;
        --desktop)      DESKTOP=1; shift ;;
        --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
        -y|--yes)       ASSUME_YES=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: install.sh [options]

Installs or upgrades the fd0 client (fd0, fd0-agent, fd0-browser-host).

  --system            install into /usr/local/bin (needs sudo)
  --prefix=DIR        install into DIR (default: ~/.local/bin)
  --version=vX.Y.Z    install a specific release tag (default: latest)
  --flavor=FLAVOR     install flavor: auto, standard, or yubikey (default: auto)
  --yubikey           shortcut for --flavor=yubikey
  --desktop           install the signed desktop bundle, including its managed CLI and agent
  --allow-downgrade   permit an explicitly selected older release
  -y, --yes           skip prompts; defaults to CLI unless a product or flavor is selected
  -h, --help          show this help

Environment:
  FD0_VERSION         same as --version
  FD0_FLAVOR          same as --flavor
  FD0_RELEASE_BASE    override the release-download base URL (for testing)
  FD0_API_BASE        override the GitHub API base URL (for testing)
EOF
            exit 0 ;;
        *)
            printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# ─── small helpers ───────────────────────────────────────────────────────
die() { printf 'fd0: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
COSIGN="${FD0_COSIGN_BIN:-cosign}"

read_reply() {
    reply=""
    if [ -r /dev/tty ] && { IFS= read -r reply < /dev/tty; } 2>/dev/null; then
        return 0
    fi
    if [ -t 0 ]; then
        IFS= read -r reply || reply=""
        return 0
    fi
    die "not a terminal; pass --yes for non-interactive use"
}

# Default Y; only `n` or `N` aborts. Reads from /dev/tty so prompts survive
# `curl … | sh`.
confirm() {
    [ "$ASSUME_YES" = "1" ] && return 0
    printf '%s [Y/n] ' "$1"
    read_reply
    case "$reply" in
        ''|y|Y|yes|YES) return 0 ;;
        *)              return 1 ;;
    esac
}

version_lt() {
    awk -v left="$1" -v right="$2" '
        function core(version) {
            sub(/\+.*/, "", version)
            sub(/-.*/, "", version)
            return version
        }
        function prerelease(version) {
            sub(/\+.*/, "", version)
            if (version !~ /-/) return ""
            sub(/^[^-]*-/, "", version)
            return version
        }
        BEGIN {
            left_core = core(left)
            right_core = core(right)
            split(left_core, left_parts, ".")
            split(right_core, right_parts, ".")
            for (i = 1; i <= 3; i++) {
                if ((left_parts[i] + 0) < (right_parts[i] + 0)) exit 0
                if ((left_parts[i] + 0) > (right_parts[i] + 0)) exit 1
            }

            left_pre = prerelease(left)
            right_pre = prerelease(right)
            if (left_pre == right_pre || left_pre == "") exit 1
            if (right_pre == "") exit 0

            left_count = split(left_pre, left_ids, ".")
            right_count = split(right_pre, right_ids, ".")
            count = left_count < right_count ? left_count : right_count
            for (i = 1; i <= count; i++) {
                left_numeric = left_ids[i] ~ /^[0-9]+$/
                right_numeric = right_ids[i] ~ /^[0-9]+$/
                if (left_numeric && right_numeric) {
                    if ((left_ids[i] + 0) < (right_ids[i] + 0)) exit 0
                    if ((left_ids[i] + 0) > (right_ids[i] + 0)) exit 1
                } else if (left_numeric != right_numeric) {
                    exit left_numeric ? 0 : 1
                } else {
                    if (left_ids[i] < right_ids[i]) exit 0
                    if (left_ids[i] > right_ids[i]) exit 1
                }
            }
            exit left_count < right_count ? 0 : 1
        }
    '
}

install_desktop() {
    desktop_yes="$1"
    desktop_installer_url="${FD0_DESKTOP_INSTALL_URL:-https://fd0.sh/install-desktop}"
    desktop_version="$VERSION"
    case "$desktop_version" in
        latest|desktop-v*) ;;
        client-v*) desktop_version="desktop-v${desktop_version#client-v}" ;;
        fd0-v*)    desktop_version="desktop-v${desktop_version#fd0-v}" ;;
        v*)        desktop_version="desktop-v${desktop_version#v}" ;;
        [0-9]*)    desktop_version="desktop-v${desktop_version}" ;;
        *) die "invalid desktop version: $desktop_version" ;;
    esac
    have curl || die "curl required for fd0 Desktop"
    curl -fsSL "$desktop_installer_url" | \
        FD0_DESKTOP_SYSTEM="$SYSTEM" \
        FD0_DESKTOP_ALLOW_DOWNGRADE="$ALLOW_DOWNGRADE" \
        FD0_DESKTOP_ASSUME_YES="$desktop_yes" \
        FD0_DESKTOP_VERSION="$desktop_version" \
        sh
}

# Install with sudo only if we're touching a system path AND we aren't root.
INSTALL_BIN() {
    src="$1"; dst="$2"
    dir=$(dirname "$dst")
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo install -d -m 0755 "$dir"
        sudo install -m 0755 "$src" "$dst"
    else
        install -d -m 0755 "$dir"
        install -m 0755 "$src" "$dst"
    fi
}

REMOVE_BIN() {
    path="$1"
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo rm -f "$path"
    else
        rm -f "$path"
    fi
}

# ─── platform detection ──────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
    linux|darwin) ;;
    *) die "unsupported OS: $OS" ;;
esac
case "$ARCH" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported arch: $ARCH" ;;
esac

# ─── detect the existing product at the target prefix ────────────────────
CURRENT=""
CURRENT_FLAVOR=""
if [ -x "$PREFIX/fd0" ]; then
    CURRENT_OUT=$("$PREFIX/fd0" version 2>/dev/null || true)
    CURRENT=$(printf '%s\n' "$CURRENT_OUT" | awk 'NR==1 {print $2}' || true)
    CURRENT_FLAVOR=$(printf '%s\n' "$CURRENT_OUT" | awk 'NR==1 {print $3}' || true)
fi
case "$CURRENT_FLAVOR" in
    yubikey|standard) ;;
    *) CURRENT_FLAVOR="standard" ;;
esac

if [ "$OS" = "darwin" ]; then
    DESKTOP_TARGET=$([ "$SYSTEM" = "1" ] && printf '/Applications/fd0.app' || printf '%s/Applications/fd0.app' "$HOME")
else
    DESKTOP_TARGET=$([ "$SYSTEM" = "1" ] && printf '/usr/local/bin/fd0-desktop' || printf '%s/.local/bin/fd0-desktop' "$HOME")
fi
CURRENT_DESKTOP=0
if [ -e "$DESKTOP_TARGET" ]; then
    CURRENT_DESKTOP=1
fi

choose_product() {
    default_product=1
    if [ "$CUSTOM_PREFIX" = "1" ] || { [ "$CURRENT_DESKTOP" != "1" ] && [ -n "$CURRENT" ]; }; then
        default_product=2
    fi

    printf '\nWhat would you like to install?\n\n'
    printf '  1) fd0 Desktop (recommended)\n'
    printf '     Includes the CLI, agent, and YubiKey support.\n\n'
    printf '  2) CLI and agent only\n\n'
    while :; do
        printf 'Select [%s]: ' "$default_product"
        read_reply
        [ -n "$reply" ] || reply=$default_product
        case "$reply" in
            1)
                if [ "$CUSTOM_PREFIX" = "1" ]; then
                    printf 'Desktop does not support --prefix; choose CLI or use --system.\n'
                    continue
                fi
                DESKTOP=1
                return 0
                ;;
            2)
                break
                ;;
            *)
                printf 'Please enter 1 or 2.\n'
                ;;
        esac
    done

    yubikey_default=n
    yubikey_hint='y/N'
    if [ "$CURRENT_FLAVOR" = "yubikey" ]; then
        yubikey_default=y
        yubikey_hint='Y/n'
    fi
    while :; do
        printf 'Include YubiKey support? [%s] ' "$yubikey_hint"
        read_reply
        [ -n "$reply" ] || reply=$yubikey_default
        case "$reply" in
            y|Y|yes|YES)
                FLAVOR=yubikey
                return 0
                ;;
            n|N|no|NO)
                FLAVOR=standard
                return 0
                ;;
            *)
                printf 'Please answer y or n.\n'
                ;;
        esac
    done
}

if [ "$ASSUME_YES" = "0" ] && [ "$DESKTOP" = "0" ] && [ "$FLAVOR_EXPLICIT" = "0" ]; then
    choose_product
fi

if [ "$DESKTOP" = "1" ]; then
    [ "$CUSTOM_PREFIX" = "0" ] || die "--prefix cannot be combined with --desktop; use --system for a system install"
    install_desktop "$ASSUME_YES"
    exit 0
fi

# ─── version resolution ──────────────────────────────────────────────────
REQUESTED_LATEST=0
if [ "$VERSION" = "latest" ]; then
    REQUESTED_LATEST=1
    have curl || die "curl required"
    CANDIDATES=$(curl -fsSL "${API_BASE}/releases?per_page=50" | awk '
        /"tag_name":/ {
            tag = $0
            sub(/^.*"tag_name": *"/, "", tag)
            sub(/".*$/, "", tag)
            next
        }
        tag != "" && /"name":/ {
            name = $0
            sub(/^.*"name": *"/, "", name)
            sub(/".*$/, "", name)
            # CLI releases are tagged vX.Y.Z. Since 0.15.0 their titles are
            # free-form, so the signing identity is derived from the tag
            # (client-vX.Y.Z) unless an old release title names it.
            if (tag ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) {
                if (name !~ /^(client|fd0)-v[0-9]+\.[0-9]+\.[0-9]+$/) {
                    name = "client-" tag
                }
                print tag "|" name
            }
            tag = ""
        }
    ')
    [ -n "$CANDIDATES" ] || die "could not resolve latest client version from ${API_BASE}"
    DOWNLOAD_TAG=""
    RELEASE_TAG=""
    BEST_VERSION=""
    for candidate in $CANDIDATES; do
        candidate_download=${candidate%%|*}
        candidate_release=${candidate#*|}
        candidate_version=${candidate_release#*-v}
        if [ -z "$BEST_VERSION" ] || version_lt "$BEST_VERSION" "$candidate_version"; then
            DOWNLOAD_TAG=$candidate_download
            RELEASE_TAG=$candidate_release
            BEST_VERSION=$candidate_version
        fi
    done
else
    case "$VERSION" in
        client-v*|fd0-v*)
            RELEASE_TAG=$VERSION
            DOWNLOAD_TAG="v${VERSION#*-v}"
            ;;
        v[0-9]*|[0-9]*)
            VERSION_NUM_INPUT=${VERSION#v}
            RELEASE_TAG="client-v${VERSION_NUM_INPUT}"
            DOWNLOAD_TAG="v${VERSION_NUM_INPUT}"
            ;;
        *) die "invalid client release tag: $VERSION" ;;
    esac
fi
printf '%s\n' "$DOWNLOAD_TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' \
    || die "invalid client download tag: $DOWNLOAD_TAG"
printf '%s\n' "$RELEASE_TAG" | grep -Eq '^(client|fd0)-v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' \
    || die "invalid client release identity: $RELEASE_TAG"
VERSION_NUM=${RELEASE_TAG#*-v}

case "$FLAVOR" in
    auto) TARGET_FLAVOR="$CURRENT_FLAVOR"; [ -n "$TARGET_FLAVOR" ] || TARGET_FLAVOR="standard" ;;
    standard|yubikey) TARGET_FLAVOR="$FLAVOR" ;;
    *) die "unknown flavor: $FLAVOR (use auto, standard, or yubikey)" ;;
esac

# Same version already there → idempotent no-op. Don't even prompt.
if [ -n "$CURRENT" ] && [ "$CURRENT" = "$VERSION_NUM" ] && [ "$CURRENT_FLAVOR" = "$TARGET_FLAVOR" ]; then
    printf 'fd0 %s %s already installed at %s\n' "$RELEASE_TAG" "$TARGET_FLAVOR" "$PREFIX"
    exit 0
fi
if printf '%s\n' "$CURRENT" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' \
    && version_lt "$VERSION_NUM" "$CURRENT"; then
    if [ "$REQUESTED_LATEST" = "1" ] || [ "$ALLOW_DOWNGRADE" != "1" ]; then
        die "refusing downgrade from $CURRENT to $VERSION_NUM; select an explicit version and pass --allow-downgrade"
    fi
fi
have "$COSIGN" || die "cosign is required to authenticate fd0 releases; install cosign and retry"

# ─── confirm install or upgrade ──────────────────────────────────────────
printf '\nfd0 client installer\n'
printf '  target:  %s\n' "$PREFIX"
if [ -n "$CURRENT" ]; then
    printf '  current: %s %s\n' "$CURRENT" "$CURRENT_FLAVOR"
    printf '  new:     %s %s\n' "$VERSION_NUM" "$TARGET_FLAVOR"
    action="upgrade"
    if version_lt "$VERSION_NUM" "$CURRENT"; then
        action="downgrade"
    fi
    if [ "$CURRENT" = "$VERSION_NUM" ] && [ "$CURRENT_FLAVOR" != "$TARGET_FLAVOR" ]; then
        action="switch flavor"
    fi
else
    printf '  version: %s %s\n' "$VERSION_NUM" "$TARGET_FLAVOR"
    action="install"
fi
printf '  verify:  sha256 + cosign (exact release workflow)\n'
printf '\n'
confirm "proceed with ${action}?" || { printf 'aborted.\n'; exit 1; }

# ─── download manifest + tarball ─────────────────────────────────────────
have curl || die "curl required"
have tar  || die "tar required"

if [ "$TARGET_FLAVOR" = "yubikey" ]; then
    TARBALL="fd0_yubikey_${OS}_${ARCH}.tar.gz"
else
    TARBALL="fd0_${OS}_${ARCH}.tar.gz"
fi
DL="${RELEASE_BASE}/download/${DOWNLOAD_TAG}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf '→ fetching %s/%s\n' "$DL" "$TARBALL"
curl -fsSL "$DL/${TARBALL}" -o "$TMP/${TARBALL}" \
    || die "could not download tarball — bad version (${RELEASE_TAG}) or no asset for ${OS}/${ARCH}?"

printf '→ fetching checksum manifest\n'
curl -fsSL "$DL/checksums.txt" -o "$TMP/checksums.txt" || die "missing checksums.txt"
printf '→ fetching and verifying cosign signature\n'
curl -fsSL "$DL/checksums.txt.sigstore.json" -o "$TMP/checksums.txt.sigstore.json" \
    || die "missing checksums.txt.sigstore.json"
IDENTITY_TAG=$(printf '%s' "$RELEASE_TAG" | sed 's/\./\\./g')
"$COSIGN" verify-blob \
    --bundle                 "$TMP/checksums.txt.sigstore.json" \
    --certificate-identity-regexp "^https://github\\.com/k2b-dev/fd0\\.sh/\\.github/workflows/release\\.yml@refs/tags/${IDENTITY_TAG}$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$TMP/checksums.txt" >/dev/null 2>&1 \
    || die "cosign verification failed — refusing to install"
printf '→ verifying tarball sha256 against manifest\n'
expected=$(awk -v t="$TARBALL" '$2 == t || $2 == "*"t {print $1}' "$TMP/checksums.txt")
[ -n "$expected" ] || die "tarball not listed in checksums.txt"
if have sha256sum; then
    actual=$(sha256sum "$TMP/${TARBALL}" | awk '{print $1}')
elif have shasum; then
    actual=$(shasum -a 256 "$TMP/${TARBALL}" | awk '{print $1}')
else
    die "need sha256sum or shasum to verify"
fi
[ "$actual" = "$expected" ] || die "sha256 mismatch — tarball does not match manifest"

# ─── install the client binaries ─────────────────────────────────────────
for bin in $REQUIRED_BINARIES; do
    # Stream only the exact expected archive members to caller-chosen files.
    # No archive member path is ever handed to tar as an extraction target.
    tar -xOzf "$TMP/${TARBALL}" "$bin" > "$TMP/$bin" \
        || die "binary $bin missing from release tarball"
    [ -s "$TMP/$bin" ] || die "binary $bin is empty in release tarball"
done
INSTALL_BINARIES="$REQUIRED_BINARIES"
MISSING_OPTIONAL_BINARIES=""
for bin in $OPTIONAL_BINARIES; do
    if tar -xOzf "$TMP/${TARBALL}" "$bin" > "$TMP/$bin" 2>/dev/null &&
       [ -s "$TMP/$bin" ]; then
        INSTALL_BINARIES="$INSTALL_BINARIES $bin"
    else
        rm -f "$TMP/$bin"
        MISSING_OPTIONAL_BINARIES="$MISSING_OPTIONAL_BINARIES $bin"
    fi
done
for bin in $MISSING_OPTIONAL_BINARIES; do
    if [ -n "$CURRENT" ] && { [ -e "$PREFIX/$bin" ] || [ -L "$PREFIX/$bin" ]; }; then
        REMOVE_BIN "$PREFIX/$bin"
        printf '✓ removed unavailable %s from %s\n' "$bin" "$PREFIX"
    fi
done
for bin in $INSTALL_BINARIES; do
    INSTALL_BIN "$TMP/$bin" "$PREFIX/$bin"
    printf '✓ %s → %s\n' "$bin" "$PREFIX/$bin"
done

# Register the narrowly-scoped Native Messaging host when it ships in the
# selected release. This is idempotent and keeps a fresh Chrome Web Store
# install from requiring a hidden terminal setup step. Browser integration is
# optional, so a registration failure must not roll back an otherwise valid
# fd0 installation.
if [ -x "$PREFIX/fd0-browser-host" ]; then
    if "$PREFIX/fd0" browser enable >/dev/null 2>&1; then
        printf '✓ Chrome browser integration enabled\n'
    else
        printf '! could not enable Chrome browser integration; retry with: fd0 browser enable\n' >&2
    fi
fi

# ─── seed client config (fresh install only) ─────────────────────────────
FD0_HOME="${FD0_HOME:-$HOME/.fd0}"
if [ -z "$CURRENT" ]; then
    mkdir -p "$FD0_HOME"
    chmod 700 "$FD0_HOME"
    if [ ! -f "$FD0_HOME/config.toml" ]; then
        cat > "$FD0_HOME/config.toml" <<EOF
# fd0 client configuration. See https://github.com/${REPO}#configuration
# for the full reference.
#
# By default the client targets the hosted fd0.sh primary (api.fd0.sh).
# fd0 writes and reads a SINGLE primary server — one ordering authority
# per scope, so replicas can never diverge. For your own server, set
# [sync].server below. For redundancy run a server-side DR backup
# (FD0_REPLICATE_FROM), not a second write target.

# [sync]
# server    = "https://your-server.example"
# interval  = "1h"
# on_unlock = true
EOF
        chmod 600 "$FD0_HOME/config.toml"
        printf '✓ wrote default config to %s/config.toml\n' "$FD0_HOME"
    fi
fi

# ─── PATH hint ───────────────────────────────────────────────────────────
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *)
        printf '\n%s is not in your PATH. Add to your shell rc:\n' "$PREFIX"
        # shellcheck disable=SC2016
        printf '    export PATH="%s:$PATH"\n' "$PREFIX"
        ;;
esac

printf '\n✓ fd0 %s %s ' "$VERSION_NUM" "$TARGET_FLAVOR"
if [ -n "$CURRENT" ]; then
    printf 'upgraded\n'
else
    printf 'installed\n  next: fd0 init\n'
fi
