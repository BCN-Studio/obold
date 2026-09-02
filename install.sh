#!/usr/bin/env bash
set -euo pipefail

REPO="BCN-Studio/obold"
BINARY_NAME="obold"

echo "======================================================"
echo "          obold :: Sovereign Dead Man Switch          "
echo "                by BCN Studio                         "
echo "======================================================"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    ARCH="x64"
    ;;
  arm64|aarch64)
    ARCH="arm64"
    ;;
  *)
    ARCH="unknown"
    ;;
esac

TARGET="${OS}-${ARCH}"
DEST_DIR=""

if [ -w "/usr/local/bin" ]; then
  DEST_DIR="/usr/local/bin"
else
  DEST_DIR="$HOME/.local/bin"
  mkdir -p "$DEST_DIR"
fi

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'obold-install')"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

INSTALLED=0

if [ "$OS" = "linux" ] || [ "$OS" = "darwin" ]; then
  if [ "$ARCH" = "x64" ] || [ "$ARCH" = "arm64" ]; then
    echo "> Detecting platform: ${TARGET}"
    RELEASE_URL="https://github.com/${REPO}/releases/latest/download/obold-${TARGET}"
    SUMS_URL="https://github.com/${REPO}/releases/latest/download/SHA256SUMS.txt"

    echo "> Downloading obold standalone binary..."
    if curl -fsSL "$RELEASE_URL" -o "$TMP_DIR/obold" 2>/dev/null; then
      if curl -fsSL "$SUMS_URL" -o "$TMP_DIR/SHA256SUMS.txt" 2>/dev/null; then
        echo "> Verifying cryptographic checksum (SHA-256)..."
        (
          cd "$TMP_DIR"
          if command -v sha256sum >/dev/null 2>&1; then
            grep "obold-${TARGET}" SHA256SUMS.txt | sed "s/obold-${TARGET}/obold/" | sha256sum -c -
          elif command -v shasum >/dev/null 2>&1; then
            grep "obold-${TARGET}" SHA256SUMS.txt | sed "s/obold-${TARGET}/obold/" | shasum -a 256 -c -
          fi
        )
      fi
      chmod 755 "$TMP_DIR/obold"
      mv "$TMP_DIR/obold" "$DEST_DIR/obold"
      INSTALLED=1
    fi
  fi
fi

if [ "$INSTALLED" -eq 0 ]; then
  echo "> Precompiled binary unavailable. Compiling via Bun runtime..."
  if ! command -v bun >/dev/null 2>&1 && [ ! -f "$HOME/.bun/bin/bun" ]; then
    echo "> Installing Bun runtime..."
    curl -fsSL https://bun.sh/install | bash
  fi
  export PATH="$HOME/.bun/bin:$PATH"

  SOURCE_DIR="$HOME/.obold-src"
  mkdir -p "$SOURCE_DIR"
  if [ -d "$SOURCE_DIR/.git" ]; then
    (cd "$SOURCE_DIR" && git pull --quiet)
  else
    git clone --depth=1 --quiet "https://github.com/${REPO}.git" "$SOURCE_DIR"
  fi

  (
    cd "$SOURCE_DIR"
    bun install --frozen-lockfile --quiet
    bun build --compile --minify --outfile="$DEST_DIR/obold" src/index.ts
  )
  chmod 755 "$DEST_DIR/obold"
fi

echo ""
echo " obold successfully installed to $DEST_DIR/obold"
echo ""
if ! echo "$PATH" | grep -q "$DEST_DIR"; then
  echo " Notice: $DEST_DIR is not in your PATH."
  echo " Add it to your shell configuration:"
  echo "   export PATH=\"$DEST_DIR:\$PATH\""
  echo ""
fi
echo " Run 'obold init' to create your first configuration."
echo " Run 'obold run' to start the sovereign daemon."
echo "======================================================"
