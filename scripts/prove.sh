#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"
INPUT="${1:-$ROOT/test/fixtures/happyPath.json}"

echo "[prove] Generating witness..."
node "$OUT/credentialAtomicQuery_js/generate_witness.js" \
  "$OUT/credentialAtomicQuery_js/credentialAtomicQuery.wasm" \
  "$INPUT" \
  "$OUT/witness.wtns"

echo "[prove] Generating Groth16 proof..."
npx snarkjs groth16 prove \
  "$OUT/credentialAtomicQuery_final.zkey" \
  "$OUT/witness.wtns" \
  "$OUT/proof.json" \
  "$OUT/public.json"

echo "[prove] Verifying proof..."
npx snarkjs groth16 verify \
  "$OUT/verification_key.json" \
  "$OUT/public.json" \
  "$OUT/proof.json"

echo "[prove] Proof size: $(wc -c < "$OUT/proof.json") bytes"
