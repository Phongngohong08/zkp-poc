"use strict";

const { buildEddsa, buildPoseidon } = require("circomlibjs");

let _eddsa = null;
let _poseidon = null;

async function getEddsa() {
  if (!_eddsa) _eddsa = await buildEddsa();
  return _eddsa;
}

async function getPoseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

// Derive BabyJubJub public key from a 32-byte private key buffer.
async function getPubKey(privKeyBytes) {
  const eddsa = await getEddsa();
  return eddsa.prv2pub(privKeyBytes);
}

// issuerId = Poseidon(pubKeyAx, pubKeyAy)
async function deriveIssuerId(pubKey) {
  const eddsa = await getEddsa();
  const poseidon = await getPoseidon();
  const Ax = eddsa.F.toObject(pubKey[0]);
  const Ay = eddsa.F.toObject(pubKey[1]);
  const h = poseidon([Ax, Ay]);
  return poseidon.F.toObject(h);
}

// Sign issuerState with the issuer's EdDSA-Poseidon private key.
// Returns { R8x, R8y, S } as BigInts, plus Ax, Ay of the public key.
async function signIssuerState(privKeyBytes, issuerState) {
  const eddsa = await getEddsa();
  const msg = eddsa.F.e(BigInt(issuerState));
  const sig = eddsa.signPoseidon(privKeyBytes, msg);
  return {
    Ax:  eddsa.F.toObject(eddsa.prv2pub(privKeyBytes)[0]),
    Ay:  eddsa.F.toObject(eddsa.prv2pub(privKeyBytes)[1]),
    R8x: eddsa.F.toObject(sig.R8[0]),
    R8y: eddsa.F.toObject(sig.R8[1]),
    S:   sig.S,
  };
}

module.exports = { getPubKey, deriveIssuerId, signIssuerState };
