# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

ZKP Credential Atomic Query — Paradigm 2 (SMT of Claims). A Circom 2.x circuit that lets a Holder prove they hold a valid issuer-signed credential satisfying a business predicate (e.g. `age ≥ 18`) without revealing identity, attribute value, or other credential fields. Follows the Iden3/Polygon ID claim-tree model.

## Commands

```bash
# Install dependencies
npm install

# Compile circuit → build/*.r1cs, build/*.wasm, build/*.sym
npm run compile          # wraps scripts/compile.sh

# Trusted-setup phase 2 (run once after compile, or after any circuit change)
npm run setup            # wraps scripts/setup.sh — downloads pot15 ptau if missing

# Run all 9 tests (requires compiled circuit + zkey)
npm test

# Run a single test by grep
npx mocha test/credentialAtomicQuery.test.js --timeout 120000 --grep "TC1"

# Generate a standalone proof from a JSON input file
npm run prove            # uses test/fixtures/happyPath.json by default
npm run prove -- path/to/input.json
```

**Important**: whenever `circuits/` files change, you must rerun both `npm run compile` AND `npm run setup` before running tests — the zkey is tied to the specific r1cs and will silently produce proofs that fail verification if stale.

## Architecture

### Circuit (Circom)

`circuits/credentialAtomicQuery.circom` is the top-level template `CredentialAtomicQuery(claimMtpDepth=20, revMtpDepth=20, rootsMtpDepth=20)`. It wires together 10 constraint groups (C1–C10) implemented as sub-templates in `circuits/lib/`:

| File | Constraint | What it enforces |
|---|---|---|
| `identity.circom` | C1 | `Poseidon(skid, nullifierSeed) == claim.subjectId` |
| `claim.circom` | C3 | `leafHash = Poseidon(6 claim fields)` |
| `predicate.circom` | C8 | attribute predicate: eq / gte / lte / range |
| `nullifier.circom` | C10 | `nullifierHash = Poseidon(nullifierSeed, contextId)` |

C2 (schema match), C4–C6 (three SMT proofs), C7 (EdDSA-Poseidon issuer signature + issuer state binding), and C9 (expiry) are all wired inline in the top-level file using circomlib components.

**SMT leaf conventions (iden3 style):**
- claimsTree: `key = leafHash, value = leafHash`
- rootsTree: `key = claimsTreeRoot, value = claimsTreeRoot`
- revocationTree: `key = revNonce, value = revNonce` (non-inclusion proof proves claim not revoked)

**Predicate encoding for range (type 3):** `predicateValue = low + high × 2^64`. The circuit decodes via `Num2Bits(128)`. For types 0/1/2 the caller must pass `predicateValue < 2^64`; the circuit always uses the low 64 bits (`predicateLow`) for single-value comparators.

### Data model

```
claim = { schemaHash, subjectId (= idcom), attributeKey, attributeValue, expiry, revNonce }
idcom = Poseidon(skid, nullifierSeed)
leafHash = Poseidon(6 claim fields)
issuerState = Poseidon(claimsTreeRoot, revocationTreeRoot, rootsTreeRoot)
issuerId = Poseidon(issuerPubKeyAx, issuerPubKeyAy)
nullifierHash = Poseidon(nullifierSeed, contextId)   ← only public output
```

### Test helpers (`test/helpers/`)

- **`smt.js`** — builds in-memory SMTs via `@iden3/js-merkletree`; exports `buildClaimsTree`, `buildRevocationTree`, `buildRootsTree`, plus proof getters. Non-inclusion proof returns `{ siblings, oldKey, oldValue, isOld0 }` — all four fields are required by `SMTVerifier`.
- **`claim.js`** — `buildClaim(params)` and `hashClaim(claim)` using circomlibjs Poseidon.
- **`eddsa.js`** — `signIssuerState(privKeyBytes, issuerState)` returns `{ Ax, Ay, R8x, R8y, S }` using circomlibjs EdDSA-Poseidon.

### Test structure

`test/credentialAtomicQuery.test.js` defines a shared `buildInputs(overrides?)` that constructs a complete, valid witness. Negative tests pass a single-field override that violates one constraint; they assert the promise is rejected (witness generation fails in the WASM, before proof generation).

TC9 (range predicate) uses `predicateValue = low + high * 2n ** 64n`.

### Build artifacts (`build/`)

| File | Purpose |
|---|---|
| `credentialAtomicQuery.r1cs` | R1CS constraint system |
| `credentialAtomicQuery_js/credentialAtomicQuery.wasm` | Witness calculator |
| `pot20_final.ptau` | Powers of Tau (hermez pot15, ~38 MB) |
| `credentialAtomicQuery_final.zkey` | Groth16 proving key |
| `verification_key.json` | Groth16 verification key |
