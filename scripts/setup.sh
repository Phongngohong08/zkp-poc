#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"
PTAU="$OUT/pot20_final.ptau"
R1CS="$OUT/credentialAtomicQuery.r1cs"
ZKEY0="$OUT/credentialAtomicQuery_0.zkey"
ZKEY_FINAL="$OUT/credentialAtomicQuery_final.zkey"

# Download powers of tau (phase 1, 2^20 sufficient for ~24k constraints)
if [ ! -f "$PTAU" ]; then
  echo "[setup] Downloading powers of tau (hermez 15)..."
  # pot15 supports up to 2^15 = 32768 constraints — enough for 24k
  PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau"
  curl -L "$PTAU_URL" -o "$PTAU"
fi

echo "[setup] Phase 2 setup..."
npx snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0"

echo "[setup] Contribute (deterministic for tests)..."
echo "test entropy 12345" | npx snarkjs zkey contribute "$ZKEY0" "$ZKEY_FINAL" --name="test" -v

echo "[setup] Export verification key..."
npx snarkjs zkey export verificationkey "$ZKEY_FINAL" "$OUT/verification_key.json"

echo "[setup] Done. zkey: $ZKEY_FINAL"
