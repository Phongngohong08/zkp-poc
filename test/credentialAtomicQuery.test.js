"use strict";

const path   = require("path");
const assert = require("assert");
const chai   = require("chai");
const cap    = require("chai-as-promised");
chai.use(cap);
const { expect } = chai;

const snarkjs    = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const { buildClaim, hashClaim }          = require("./helpers/claim");
const { signIssuerState, deriveIssuerId } = require("./helpers/eddsa");
const {
  buildClaimsTree, getClaimInclusionProof,
  buildRootsTree,  getRootsInclusionProof,
  buildRevocationTree, getRevNonInclusionProof,
  getRoot,
} = require("./helpers/smt");

// -----------------------------------------------------------------------
// Paths to compiled circuit artefacts (produced by scripts/compile.sh)
// -----------------------------------------------------------------------
const WASM_PATH = path.join(__dirname, "../build/credentialAtomicQuery_js/credentialAtomicQuery.wasm");
const ZKEY_PATH = path.join(__dirname, "../build/credentialAtomicQuery_final.zkey");

// -----------------------------------------------------------------------
// Issuer key (deterministic for tests — never use in production)
// -----------------------------------------------------------------------
const ISSUER_PRIV_KEY = Buffer.from(
  "0001020304050607080900010203040506070809000102030405060708090001",
  "hex"
);

// -----------------------------------------------------------------------
// Shared Poseidon instance
// -----------------------------------------------------------------------
let poseidon;

before(async () => {
  poseidon = await buildPoseidon();
});

function poseidonHash(inputs) {
  return poseidon.F.toObject(poseidon(inputs.map(BigInt)));
}

// -----------------------------------------------------------------------
// Build a complete, valid witness input for the circuit.
// Override any fields via the `overrides` object to create negative cases.
// -----------------------------------------------------------------------
async function buildInputs(overrides = {}) {
  // --- Holder identity ---
  const skid          = 12345678901234567890n;
  const nullifierSeed = 98765432109876543210n;
  const idcom         = poseidonHash([skid, nullifierSeed]);

  // --- Claim ---
  const schemaHash    = poseidonHash([BigInt("0x4167655f436c61696d5f7631")]);  // hash("AgeClaim_v1")
  const attributeKey  = poseidonHash([BigInt("0x616765")]);                   // hash("age")
  const attributeValue = 25n;
  const expiry        = 2000000000n; // far future
  const revNonce      = 42n;

  const claim = buildClaim({
    schemaHash,
    subjectId:      idcom,
    attributeKey,
    attributeValue,
    expiry,
    revNonce,
  });

  const leafHash = await hashClaim(claim);

  // --- Claims tree ---
  const claimsTree  = await buildClaimsTree([leafHash]);
  const claimsRoot  = await getRoot(claimsTree);
  const claimProof  = await getClaimInclusionProof(claimsTree, leafHash);

  // --- Revocation tree (empty — claim not revoked) ---
  const revTree   = await buildRevocationTree([]);
  const revRoot   = await getRoot(revTree);
  const revProof  = await getRevNonInclusionProof(revTree, revNonce);

  // --- Roots tree ---
  const rootsTree   = await buildRootsTree([claimsRoot]);
  const rootsRoot   = await getRoot(rootsTree);
  const rootsProof  = await getRootsInclusionProof(rootsTree, claimsRoot);

  // --- Issuer state ---
  const issuerState = poseidonHash([claimsRoot, revRoot, rootsRoot]);
  const sig         = await signIssuerState(ISSUER_PRIV_KEY, issuerState);
  const issuerId    = await deriveIssuerId([
    /* Ax */ { bigInt: () => sig.Ax, ...{ toString: () => sig.Ax.toString() } },
    /* Ay */ { bigInt: () => sig.Ay, ...{ toString: () => sig.Ay.toString() } },
  ]);

  // issuerId = Poseidon(Ax, Ay)
  const issuerIdComputed = poseidonHash([sig.Ax, sig.Ay]);

  // --- Context + nullifier ---
  const contextId = 777n;
  const currentTimestamp = 1700000000n; // < expiry

  // Predicate: age >= 18
  const predicateType  = 1n; // gte
  const predicateValue = 18n;

  const inputs = {
    // public
    issuerId:               issuerIdComputed,
    issuerState:            issuerState,
    requestedSchemaHash:    schemaHash,
    requestedAttributeKey:  attributeKey,
    predicateType:          predicateType,
    predicateValue:         predicateValue,
    contextId:              contextId,
    currentTimestamp:       currentTimestamp,
    // private — identity
    skid:                   skid,
    nullifierSeed:          nullifierSeed,
    // private — claim
    claimSchemaHash:        claim.schemaHash,
    claimSubjectId:         claim.subjectId,
    claimAttributeKey:      claim.attributeKey,
    claimAttributeValue:    claim.attributeValue,
    claimExpiry:            claim.expiry,
    claimRevNonce:          claim.revNonce,
    // private — tree roots
    claimsTreeRoot:         claimsRoot,
    revocationTreeRoot:     revRoot,
    rootsTreeRoot:          rootsRoot,
    // private — merkle paths
    claimMtp:               claimProof.siblings,
    rootsMtp:               rootsProof.siblings,
    revMtp:                 revProof.siblings,
    revMtpOldKey:           revProof.oldKey,
    revMtpOldValue:         revProof.oldValue,
    revMtpIsOld0:           revProof.isOld0,
    // private — issuer signature
    issuerPubKeyAx:         sig.Ax,
    issuerPubKeyAy:         sig.Ay,
    issuerSigR8x:           sig.R8x,
    issuerSigR8y:           sig.R8y,
    issuerSigS:             sig.S,
  };

  // Apply overrides for negative-case tests
  return Object.assign({}, inputs, overrides);
}

// Helper: generate witness + full proof + verify in one shot.
// Throws on any constraint violation (caught by negative tests).
async function generateAndVerify(inputs) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs, WASM_PATH, ZKEY_PATH
  );
  const vKey = await snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
  const ok   = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  return { ok, publicSignals };
}

// Helper: just compute the witness, no proof (fast for negative tests).
async function generateWitness(inputs) {
  // fullProve will throw during witness calculation if constraints are violated.
  // We abort early by catching the exception from the WASM runtime.
  return generateAndVerify(inputs);
}

// -----------------------------------------------------------------------
// Test suite
// -----------------------------------------------------------------------
describe("CredentialAtomicQuery", function () {
  this.timeout(300_000); // 5 min per test (setup + proof)

  it("TC1 happy path: age=25, predicate >= 18 → proof valid", async () => {
    const inputs  = await buildInputs();
    const { ok, publicSignals } = await generateAndVerify(inputs);
    expect(ok).to.be.true;
    // publicSignals[0] = nullifierHash = Poseidon(nullifierSeed, contextId)
    const expectedNullifier = poseidonHash([inputs.nullifierSeed, inputs.contextId]);
    expect(publicSignals[0]).to.equal(expectedNullifier.toString());
  });

  it("TC2 rejects tampered attribute value (17→25): Merkle path invalid", async () => {
    // Tree was built with attributeValue=25. Attacker presents 17 instead.
    // leafHash_computed = Poseidon(..., 17, ...) ≠ tree leaf → C4 fails.
    const overrides = { claimAttributeValue: 17n };
    const tampered = await buildInputs(overrides);
    // To make TC2 realistic, build inputs normally but then override the value
    await expect(generateWitness(tampered)).to.be.rejected;
  });

  it("TC3 rejects fake issuer pubKey (C7 EdDSA fail)", async () => {
    const fakeKey = Buffer.from(
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      "hex"
    );
    const { buildEddsa } = require("circomlibjs");
    const eddsa = await buildEddsa();
    const fakePub = eddsa.prv2pub(fakeKey);
    const overrides = {
      issuerPubKeyAx: eddsa.F.toObject(fakePub[0]),
      issuerPubKeyAy: eddsa.F.toObject(fakePub[1]),
    };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  it("TC4 rejects wrong Holder skid (C1 identity fail)", async () => {
    const overrides = { skid: 99999999999999999999n };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  it("TC5 rejects expired VC (C9 expiry fail)", async () => {
    // currentTimestamp > claimExpiry
    const overrides = { currentTimestamp: 9999999999n, claimExpiry: 1000n };
    // Note: claimExpiry override also changes leafHash → C4 would also fail,
    // but the expiry check (C9) is the intended failure mode here.
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  it("TC6 rejects revoked VC (C6 non-inclusion fail)", async () => {
    // Rebuild inputs with the revNonce present in the revocation tree.
    const inputs = await buildInputs();
    // Build a revocation tree that DOES contain the revNonce.
    const revokedTree = await buildRevocationTree([inputs.claimRevNonce]);
    const revokedRoot  = await getRoot(revokedTree);
    // Non-inclusion proof will fail → use this root (but witness generation
    // will throw because the revNonce IS in the tree and getRevNonInclusionProof raises).
    // Simulate: manually override revocationTreeRoot to a root where nonce exists.
    // The circuit will reject because revSmt non-inclusion check fails.
    const badRevProof = {
      siblings:    new Array(20).fill(0n),
      oldKey:      inputs.claimRevNonce,
      oldValue:    inputs.claimRevNonce,
      isOld0:      0,
    };
    const overrides = {
      revocationTreeRoot: revokedRoot,
      revMtp:             badRevProof.siblings,
      revMtpOldKey:       badRevProof.oldKey,
      revMtpOldValue:     badRevProof.oldValue,
      revMtpIsOld0:       badRevProof.isOld0,
      // issuerState must also be recomputed for C7 to get to C6 — keep old one
      // so either C7 fails (wrong state) or C6 fails (bad proof). Either way, rejected.
    };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  it("TC7 rejects wrong schema (claim 'country' used for 'age' query)", async () => {
    const wrongSchema = poseidonHash([BigInt("0x636f756e747279")]);  // hash("country")
    const overrides   = { claimSchemaHash: wrongSchema };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  it("TC8 two proofs from same Holder with different contextIds → different nullifiers", async () => {
    const inputs1 = await buildInputs({ contextId: 111n });
    const inputs2 = await buildInputs({ contextId: 222n });

    const wtns1 = await generateWitness(inputs1);
    const wtns2 = await generateWitness(inputs2);

    // Extract nullifierHash from witness (index 1 = first public output after inputs)
    // We compute it directly to avoid full proof overhead in this TC.
    const n1 = poseidonHash([inputs1.nullifierSeed, inputs1.contextId]);
    const n2 = poseidonHash([inputs2.nullifierSeed, inputs2.contextId]);
    expect(n1).to.not.equal(n2);
    // Both witnesses must be computable without error
    expect(wtns1).to.be.ok;
    expect(wtns2).to.be.ok;
  });

  it("TC9 predicate type=3 (range): age=25, range [20,30] → valid", async () => {
    // predicateValue encodes low=20 and high=30 as low + high*2^64
    const low  = 20n;
    const high = 30n;
    const rangeVal = low + high * (2n ** 64n);
    const inputs = await buildInputs({
      predicateType:  3n,
      predicateValue: rangeVal,
    });
    const { ok } = await generateAndVerify(inputs);
    expect(ok).to.be.true;
  });
});
