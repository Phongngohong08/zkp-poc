"use strict";

const { buildPoseidon } = require("circomlibjs");

let _poseidon = null;

async function getPoseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

// Build a claim object with defaults for optional fields.
function buildClaim({
  schemaHash,
  subjectId,
  attributeKey,
  attributeValue,
  expiry,
  revNonce,
}) {
  return { schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce };
}

// Compute leafHash = Poseidon(schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce)
async function hashClaim(claim) {
  const poseidon = await getPoseidon();
  const h = poseidon([
    BigInt(claim.schemaHash),
    BigInt(claim.subjectId),
    BigInt(claim.attributeKey),
    BigInt(claim.attributeValue),
    BigInt(claim.expiry),
    BigInt(claim.revNonce),
  ]);
  return poseidon.F.toObject(h);
}

module.exports = { buildClaim, hashClaim };
