#!/usr/bin/env bash
set -euo pipefail

CIRCOM="${CIRCOM_BIN:-$(which circom 2>/dev/null || echo "$HOME/bin/circom")}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"

mkdir -p "$OUT"

echo "[compile] Compiling circuit..."
"$CIRCOM" "$ROOT/circuits/credentialAtomicQuery.circom" \
  --r1cs --wasm --sym \
  -o "$OUT" \
  -l "$ROOT/node_modules"

echo "[compile] Done. Constraints:"
npx snarkjs r1cs info "$OUT/credentialAtomicQuery.r1cs" | grep -E "Constraints|Variables"
