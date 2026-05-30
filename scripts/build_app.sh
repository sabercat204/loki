#!/usr/bin/env bash
# Build the Loki native app bundle.
#
# Usage:
#   ./scripts/build_app.sh              # macOS, ad-hoc signed
#   ./scripts/build_app.sh --sign       # macOS, prompts for Apple Developer identity
#   ./scripts/build_app.sh --platform windows
#   ./scripts/build_app.sh --platform linux
#
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-.venv/bin/python}"
PLATFORM="macOS"
SIGN_FLAG="--adhoc-sign"
FORMAT="app"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign)
            SIGN_FLAG=""
            shift
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 1
            ;;
    esac
done

case "$PLATFORM" in
    macOS)
        FORMAT="app"
        ;;
    windows)
        FORMAT="app"
        ;;
    linux)
        FORMAT="appimage"
        ;;
    *)
        echo "Unknown platform: $PLATFORM (use macOS, windows, or linux)" >&2
        exit 1
        ;;
esac

echo "==> Creating $PLATFORM $FORMAT scaffold..."
$PYTHON -m briefcase create "$PLATFORM" "$FORMAT" 2>/dev/null || true

echo "==> Updating app sources..."
$PYTHON -m briefcase update "$PLATFORM" "$FORMAT"

echo "==> Building app..."
$PYTHON -m briefcase build "$PLATFORM" "$FORMAT"

echo "==> Packaging..."
if [[ -n "$SIGN_FLAG" ]]; then
    $PYTHON -m briefcase package "$PLATFORM" "$FORMAT" $SIGN_FLAG
else
    $PYTHON -m briefcase package "$PLATFORM" "$FORMAT"
fi

echo ""
echo "Done. Output:"
ls -lh dist/Loki-* 2>/dev/null || echo "(check dist/ directory)"
