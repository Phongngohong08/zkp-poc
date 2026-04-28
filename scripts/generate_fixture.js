"use strict";

// Generates test/fixtures/happyPath.json — the canonical happy-path input for prove.sh.
// Uses identical logic to buildInputs() in credentialAtomicQuery.test.js.

const path = require("path");
const fs   = require("fs");
const { buildPoseidon }  = require("circomlibjs");
const { buildClaim, hashClaim }           = require("../test/helpers/claim");
const { signIssuerState }                 = require("../test/helpers/eddsa");
const {
  buildClaimsTree, getClaimInclusionProof,
  buildRootsTree,  getRootsInclusionProof,
  buildRevocationTree, getRevNonInclusionProof,
  getRoot,
} = require("../test/helpers/smt");

const ISSUER_PRIV_KEY = Buffer.from(
  "0001020304050607080900010203040506070809000102030405060708090001",
  "hex"
);

async function main() {
  const poseidon = await buildPoseidon();
  const H = (inputs) => poseidon.F.toObject(poseidon(inputs.map(BigInt)));

  const skid          = 12345678901234567890n;
  const nullifierSeed = 98765432109876543210n;
  const idcom         = H([skid, nullifierSeed]);

  const schemaHash     = H([BigInt("0x4167655f436c61696d5f7631")]);
  const attributeKey   = H([BigInt("0x616765")]);
  const attributeValue = 25n;
  const expiry         = 2000000000n;
  const revNonce       = 42n;

  const claim    = buildClaim({ schemaHash, subjectId: idcom, attributeKey, attributeValue, expiry, revNonce });
  const leafHash = await hashClaim(claim);

  const claimsTree = await buildClaimsTree([leafHash]);
  const claimsRoot = await getRoot(claimsTree);
  const claimProof = await getClaimInclusionProof(claimsTree, leafHash);

  const revTree  = await buildRevocationTree([]);
  const revRoot  = await getRoot(revTree);
  const revProof = await getRevNonInclusionProof(revTree, revNonce);

  const rootsTree  = await buildRootsTree([claimsRoot]);
  const rootsRoot  = await getRoot(rootsTree);
  const rootsProof = await getRootsInclusionProof(rootsTree, claimsRoot);

  const issuerState = H([claimsRoot, revRoot, rootsRoot]);
  const sig         = await signIssuerState(ISSUER_PRIV_KEY, issuerState);
  const issuerId    = H([sig.Ax, sig.Ay]);

  const contextId        = 777n;
  const currentTimestamp = 1700000000n;
  const predicateType    = 1n;
  const predicateValue   = 18n;

  const inputs = {
    issuerId,
    issuerState,
    requestedSchemaHash:   schemaHash,
    requestedAttributeKey: attributeKey,
    predicateType,
    predicateValue,
    contextId,
    currentTimestamp,
    skid,
    nullifierSeed,
    claimSchemaHash:      claim.schemaHash,
    claimSubjectId:       claim.subjectId,
    claimAttributeKey:    claim.attributeKey,
    claimAttributeValue:  claim.attributeValue,
    claimExpiry:          claim.expiry,
    claimRevNonce:        claim.revNonce,
    claimsTreeRoot:       claimsRoot,
    revocationTreeRoot:   revRoot,
    rootsTreeRoot:        rootsRoot,
    claimMtp:             claimProof.siblings,
    rootsMtp:             rootsProof.siblings,
    revMtp:               revProof.siblings,
    revMtpOldKey:         revProof.oldKey,
    revMtpOldValue:       revProof.oldValue,
    revMtpIsOld0:         revProof.isOld0,
    issuerPubKeyAx:       sig.Ax,
    issuerPubKeyAy:       sig.Ay,
    issuerSigR8x:         sig.R8x,
    issuerSigR8y:         sig.R8y,
    issuerSigS:           sig.S,
  };

  // snarkjs requires all values as strings (or numbers for small integers)
  const json = JSON.stringify(inputs, (_k, v) =>
    typeof v === "bigint" ? v.toString() : v, 2);

  const outPath = path.join(__dirname, "../test/fixtures/happyPath.json");
  fs.writeFileSync(outPath, json);
  console.log("[generate_fixture] Written:", outPath);
}

main().catch((e) => { console.error(e); process.exit(1); });
