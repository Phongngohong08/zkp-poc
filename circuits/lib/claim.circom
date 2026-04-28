pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// C3 — Claim Leaf Hash Computation
// leafHash = Poseidon(schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce)
template ClaimHasher() {
    signal input schemaHash;
    signal input subjectId;
    signal input attributeKey;
    signal input attributeValue;
    signal input expiry;
    signal input revNonce;

    signal output leafHash;

    component hasher = Poseidon(6);
    hasher.inputs[0] <== schemaHash;
    hasher.inputs[1] <== subjectId;
    hasher.inputs[2] <== attributeKey;
    hasher.inputs[3] <== attributeValue;
    hasher.inputs[4] <== expiry;
    hasher.inputs[5] <== revNonce;

    leafHash <== hasher.out;
}
