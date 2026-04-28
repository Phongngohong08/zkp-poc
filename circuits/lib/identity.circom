pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// C1 — Identity Ownership
// Proves that the Holder knows skid such that Poseidon(skid, nullifierSeed) == claim.subjectId
template IdentityOwnership() {
    signal input skid;
    signal input nullifierSeed;
    signal input claimSubjectId;

    signal output idcom;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== skid;
    hasher.inputs[1] <== nullifierSeed;

    idcom <== hasher.out;

    // Enforce that the computed idcom matches the subjectId in the claim
    idcom === claimSubjectId;
}
