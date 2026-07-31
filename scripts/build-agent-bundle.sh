#!/usr/bin/env bash
# Build a single-file tunnelcat.pyz that runs on a target with nothing but
# python3 installed (no pip/venv/internet needed on the target). Requires
# `pip wheel .` output or a built wheel in dist/, and `shiv` on the build
# machine (`pip install shiv`).
#
# Usage: scripts/build-agent-bundle.sh [platform] [python-version]
#   scripts/build-agent-bundle.sh                          # linux x86_64, py3.11
#   scripts/build-agent-bundle.sh manylinux2014_aarch64 311 # linux arm64, py3.11
set -euo pipefail

PLATFORM="${1:-manylinux2014_x86_64}"
PYVER="${2:-311}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m pip wheel --quiet --no-deps -w dist .

WHEEL="$(ls -t dist/tunnelcat-*.whl | head -1)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "Resolving deps for platform=$PLATFORM python=$PYVER..."
python3 -m pip install --quiet --target "$BUILD_DIR" \
  --platform "$PLATFORM" --python-version "$PYVER" \
  --implementation cp --abi "cp${PYVER}" --only-binary=:all: \
  "$WHEEL"

echo "Packing shiv bundle..."
python3 -m shiv --site-packages "$BUILD_DIR" \
  -e "tunnelcat.cli:main" \
  -o dist/tunnelcat.pyz \
  -p "/usr/bin/env python3" \
  --compressed

chmod +x dist/tunnelcat.pyz
echo "Built dist/tunnelcat.pyz ($(du -h dist/tunnelcat.pyz | cut -f1)) for $PLATFORM / cp$PYVER"
