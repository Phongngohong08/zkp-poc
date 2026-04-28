pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// C10 — Nullifier Computation
// nullifierHash = Poseidon(nullifierSeed, contextId)
// Binds the nullifier to a specific session/context to prevent replay attacks.
// Two proofs from the same Holder with different contextIds produce different nullifiers (unlinkability).
template NullifierHasher() {
    signal input nullifierSeed;
    signal input contextId;

    signal output nullifierHash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== nullifierSeed;
    hasher.inputs[1] <== contextId;

    nullifierHash <== hasher.out;
}
