#!/usr/bin/env bash
# Re-sign a Loki macOS artifact with a local Personal Team certificate.
#
# Loki's CI publishes ad-hoc-signed DMGs (no Apple Developer ID; no
# notarization) on every v* tag. This script re-signs a downloaded
# artifact with whatever Apple Development certificate is in your
# Keychain — typically the free Personal Team cert that Xcode creates
# from a regular Apple ID. The result still won't be notarized (that
# requires the paid program) but it WILL be trusted by the local
# Keychain that issued the cert, which is enough for personal use.
#
# Usage:
#   ./scripts/codesign_local_macos.sh <input.dmg | input.app> [--identity <name>] [--out <path>]
#
# Examples:
#   ./scripts/codesign_local_macos.sh ~/Downloads/Loki-macOS-dmg.zip
#   ./scripts/codesign_local_macos.sh dist/Loki-1.0.0.dmg --identity "Apple Development: dan (XYZ)"
#   ./scripts/codesign_local_macos.sh /Volumes/Loki/Loki.app --out ~/Applications
#
# Behavior:
# - If the input is a zip (the GitHub Actions artifact download), it is
#   unzipped to a temp dir and the inner DMG is processed.
# - If the input is a DMG, it is mounted read-only, the .app inside is
#   copied to the output dir, and the volume is detached.
# - If the input is a .app already, it is copied (or re-signed in place
#   if --in-place is given).
# - The .app is then re-signed with `codesign --force --deep --sign`.
# - --identity defaults to the first "Apple Development: ..." identity
#   in your login Keychain. Use `security find-identity -v` to list.
# - --out defaults to ./dist/local-signed/.
# - Re-running on the same input is idempotent: it overwrites the
#   previous output.
#
# Requirements: macOS, Xcode command-line tools (codesign, hdiutil),
# unzip. No paid Developer ID or Apple Developer Program membership
# needed.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script only runs on macOS" >&2
    exit 1
fi

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

INPUT=""
IDENTITY=""
OUT_DIR="dist/local-signed"
IN_PLACE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage 0
            ;;
        --identity)
            IDENTITY="$2"
            shift 2
            ;;
        --out)
            OUT_DIR="$2"
            shift 2
            ;;
        --in-place)
            IN_PLACE=1
            shift
            ;;
        --)
            shift
            INPUT="${1:-}"
            shift || true
            break
            ;;
        -*)
            echo "error: unknown flag: $1" >&2
            usage 1
            ;;
        *)
            if [[ -z "$INPUT" ]]; then
                INPUT="$1"
                shift
            else
                echo "error: unexpected argument: $1" >&2
                usage 1
            fi
            ;;
    esac
done

if [[ -z "$INPUT" ]]; then
    echo "error: no input file given" >&2
    usage 1
fi

if [[ ! -e "$INPUT" ]]; then
    echo "error: input does not exist: $INPUT" >&2
    exit 1
fi

# Resolve the signing identity if not provided.
if [[ -z "$IDENTITY" ]]; then
    IDENTITY="$(security find-identity -v -p codesigning login.keychain-db 2>/dev/null \
        | awk -F'"' '/Apple Development:/ {print $2; exit}')"
    if [[ -z "$IDENTITY" ]]; then
        echo "error: no 'Apple Development:' identity found in login.keychain-db." >&2
        echo "       Open Xcode → Settings → Accounts and add your Apple ID; Xcode" >&2
        echo "       will create a Personal Team certificate automatically." >&2
        echo "       Or pass --identity 'Apple Development: <Name> (TEAM)' explicitly." >&2
        exit 1
    fi
    echo "==> Auto-detected signing identity: $IDENTITY"
fi

mkdir -p "$OUT_DIR"

# Stage a working tree for the .app extraction. mktemp -d is auto-cleaned
# on exit via trap.
WORK="$(mktemp -d -t loki-codesign.XXXXXX)"
cleanup() {
    # Detach any volumes we mounted under WORK.
    if mount | grep -q "$WORK/mnt"; then
        hdiutil detach "$WORK/mnt" -quiet || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# Determine input type and extract the .app.
APP_BUNDLE=""
APP_NAME=""

extract_from_dmg() {
    local dmg="$1"
    mkdir -p "$WORK/mnt"
    echo "==> Mounting $dmg ..."
    hdiutil attach "$dmg" -mountpoint "$WORK/mnt" -nobrowse -readonly -quiet
    local found
    found="$(find "$WORK/mnt" -maxdepth 2 -name "*.app" -print -quit)"
    if [[ -z "$found" ]]; then
        echo "error: no .app bundle inside $dmg" >&2
        exit 1
    fi
    APP_NAME="$(basename "$found")"
    echo "==> Copying $APP_NAME from DMG ..."
    cp -R "$found" "$WORK/$APP_NAME"
    APP_BUNDLE="$WORK/$APP_NAME"
    hdiutil detach "$WORK/mnt" -quiet
}

case "$INPUT" in
    *.zip)
        echo "==> Unzipping $INPUT ..."
        unzip -q "$INPUT" -d "$WORK"
        local_dmg="$(find "$WORK" -maxdepth 2 -name "*.dmg" -print -quit)"
        if [[ -z "$local_dmg" ]]; then
            echo "error: no .dmg found inside $INPUT" >&2
            exit 1
        fi
        extract_from_dmg "$local_dmg"
        ;;
    *.dmg)
        extract_from_dmg "$INPUT"
        ;;
    *.app)
        APP_NAME="$(basename "$INPUT")"
        if [[ "$IN_PLACE" -eq 1 ]]; then
            APP_BUNDLE="$INPUT"
        else
            echo "==> Copying $APP_NAME ..."
            cp -R "$INPUT" "$WORK/$APP_NAME"
            APP_BUNDLE="$WORK/$APP_NAME"
        fi
        ;;
    *)
        echo "error: unsupported input type: $INPUT (expected .zip / .dmg / .app)" >&2
        exit 1
        ;;
esac

# Strip the quarantine attribute first; codesign will fail on quarantined
# binaries inherited from CI. -cr is recursive + idempotent; ignore the
# exit code because xattr returns 1 if the attribute isn't present.
echo "==> Stripping com.apple.quarantine ..."
xattr -cr "$APP_BUNDLE" 2>/dev/null || true

# Re-sign. --deep walks every nested binary; --force overwrites any
# existing signature (including the ad-hoc one from CI).
echo "==> Signing $APP_NAME with: $IDENTITY"
codesign --force --deep --sign "$IDENTITY" \
    --options runtime \
    --timestamp=none \
    "$APP_BUNDLE"

echo "==> Verifying ..."
codesign --verify --verbose=2 "$APP_BUNDLE"

# Move to OUT_DIR. If the destination already has the .app, replace it.
DEST="$OUT_DIR/$APP_NAME"
if [[ -e "$DEST" ]]; then
    rm -rf "$DEST"
fi
if [[ "$APP_BUNDLE" != "$DEST" ]]; then
    cp -R "$APP_BUNDLE" "$DEST"
fi

echo ""
echo "Signed: $DEST"
echo ""
echo "To install: drag '$DEST' into /Applications. The first launch will"
echo "still prompt Gatekeeper because the certificate is from your local"
echo "Keychain, not the paid Apple Developer program — right-click the"
echo "app and choose 'Open' to whitelist it for subsequent launches."
