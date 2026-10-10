#!/bin/sh
# droot prebuilt-payload downloader
#
# One-liner install of the CI-compiled static exploit payloads:
#
#   curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/droot/main/scripts/droot-download.sh | sh
#
# Downloads droot-payloads-<tag>-linux-<arch>.tar.gz from the latest release,
# verifies every binary against the bundled sha256 manifest, and installs the
# payloads into ~/.droot/prebuilt (override with --out DIR). Payloads stay
# runnable without a compiler on the target box.
#
# Flags:
#   --tag vX.Y.Z   install a specific release (default: latest)
#   --out DIR      install directory (default: ~/.droot/prebuilt)
#   -h, --help     this help
#
# droot -- Linux LPE toolkit. Author: baba01hacker.
set -eu

REPO="Baba01hacker666/droot"
BASE_URL="https://github.com/$REPO/releases"
DEST="${DROOT_PREBUILT_DIR:-$HOME/.droot/prebuilt}"
TAG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --out) DEST="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    aarch64|arm64)  ARCH="aarch64" ;;
    *) echo "unsupported arch: $ARCH (x86_64/aarch64 only)" >&2; exit 1 ;;
esac

if [ -z "$TAG" ]; then
    # resolve the latest tag without jq: plain grep on the redirect URL
    if command -v curl >/dev/null 2>&1; then
        TAG=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
              "$BASE_URL/latest" | sed 's|.*/tag/||') || true
    elif command -v wget >/dev/null 2>&1; then
        TAG=$(wget -qO- --max-redirect=0 "$BASE_URL/latest" 2>/dev/null \
              | sed -n 's|.*/tag/\([^"]*\)".*|\1|p' | head -1) || true
    else
        echo "need curl or wget" >&2; exit 1
    fi
    [ -n "$TAG" ] || { echo "could not resolve latest release tag" >&2; exit 1; }
fi

ASSET="droot-payloads-$TAG-linux-$ARCH.tar.gz"
URL="$BASE_URL/download/$TAG/$ASSET"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "[*] droot $TAG ($ARCH) -> $DEST"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$TMP/$ASSET" "$URL"
else
    wget -qO "$TMP/$ASSET" "$URL"
fi

# verify against the manifest bundled inside the tarball
if ! tar -xzf "$TMP/$ASSET" -C "$TMP" payloads/manifest.json 2>/dev/null; then
    echo "[-] no manifest.json in release asset -- refusing to install" >&2
    exit 1
fi
[ -f "$TMP/payloads/manifest.json" ] || {
    echo "[-] manifest.json missing after extraction -- refusing to install" >&2
    exit 1
}

fail=0
while read -r name want; do
    got=$(sha256sum "$TMP/payloads/$name" 2>/dev/null | cut -d' ' -f1) || {
        fail=1; echo "[-] missing payload: $name" >&2; continue; }
    if [ "$got" != "$want" ]; then
        fail=1
        echo "[-] sha256 mismatch: $name" >&2
        echo "      manifest: $want" >&2
        echo "      actual:   $got" >&2
    fi
done <<EOF
$(sed -n 's/.*"\([^"]*\)": *{[^}]*"sha256": *"\([0-9a-f]\{64\}\)".*/\1 \2/p' \
    "$TMP/payloads/manifest.json")
EOF
[ "$fail" -eq 0 ] || { echo "[-] integrity check failed" >&2; exit 1; }
[ -n "$(sha256sum "$TMP/payloads/dirtycow" | cut -d' ' -f1)" ] || {
    echo "[-] manifest verification checked nothing -- refusing" >&2; exit 1; }

tar -xzf "$TMP/$ASSET" -C "$TMP" payloads
mkdir -p "$DEST"
cp -r "$TMP/payloads/." "$DEST/"
chmod +x "$DEST"/* 2>/dev/null || true

n=$(find "$DEST" -type f ! -name manifest.json | wc -l)
echo "[+] $n payloads installed in $DEST (sha256 verified)"
echo "[*] run them directly, or point droot at them with DROOT_PREBUILT_DIR=$DEST"
