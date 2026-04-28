pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

include "./lib/identity.circom";
include "./lib/claim.circom";
include "./lib/nullifier.circom";
include "./lib/predicate.circom";

// CredentialAtomicQuery — Paradigm 2 (SMT of Claims)
//
// Security goals: Authenticity, Integrity, Ownership,
//   Non-revocation, Replay protection, Unlinkability.
//
// SMT leaf convention (iden3 style):
//   claimsTree:      key = leafHash, value = leafHash
//   rootsTree:       key = claimsTreeRoot, value = claimsTreeRoot
//   revocationTree:  key = revNonce, value = 0 (proved absent)
//
// Depth 20 for all trees (~1M leaves each, suitable for a POC).

template CredentialAtomicQuery(claimMtpDepth, revMtpDepth, rootsMtpDepth) {

    // =========================================================
    // PUBLIC INPUTS
    // =========================================================
    signal input issuerId;
    signal input issuerState;
    signal input requestedSchemaHash;
    signal input requestedAttributeKey;
    signal input predicateType;
    signal input predicateValue;
    signal input contextId;
    signal input currentTimestamp;

    // PUBLIC OUTPUT
    signal output nullifierHash;

    // =========================================================
    // PRIVATE INPUTS
    // =========================================================
    signal input skid;
    signal input nullifierSeed;

    // Claim fields
    signal input claimSchemaHash;
    signal input claimSubjectId;
    signal input claimAttributeKey;
    signal input claimAttributeValue;
    signal input claimExpiry;
    signal input claimRevNonce;

    // Tree roots (private — linked by C7 to the public issuerState)
    signal input claimsTreeRoot;
    signal input revocationTreeRoot;
    signal input rootsTreeRoot;

    // C4: inclusion proof for claim in claimsTree
    signal input claimMtp[claimMtpDepth];

    // C5: inclusion proof for claimsTreeRoot in rootsTree
    signal input rootsMtp[rootsMtpDepth];

    // C6: non-inclusion proof for revNonce in revocationTree
    // The Holder supplies the adjacent leaf (or 0/0 with isOld0=1 for empty path).
    signal input revMtp[revMtpDepth];
    signal input revMtpOldKey;
    signal input revMtpOldValue;
    signal input revMtpIsOld0;

    // Issuer EdDSA-Poseidon signature
    signal input issuerPubKeyAx;
    signal input issuerPubKeyAy;
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    // =========================================================
    // C1 — Identity Ownership
    // =========================================================
    component identityCheck = IdentityOwnership();
    identityCheck.skid           <== skid;
    identityCheck.nullifierSeed  <== nullifierSeed;
    identityCheck.claimSubjectId <== claimSubjectId;

    // =========================================================
    // C2 — Schema & Attribute Key Match
    // =========================================================
    claimSchemaHash   === requestedSchemaHash;
    claimAttributeKey === requestedAttributeKey;

    // =========================================================
    // C3 — Claim Leaf Hash
    // =========================================================
    component claimHasher = ClaimHasher();
    claimHasher.schemaHash     <== claimSchemaHash;
    claimHasher.subjectId      <== claimSubjectId;
    claimHasher.attributeKey   <== claimAttributeKey;
    claimHasher.attributeValue <== claimAttributeValue;
    claimHasher.expiry         <== claimExpiry;
    claimHasher.revNonce       <== claimRevNonce;
    // leafHash = Poseidon(schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce)

    // =========================================================
    // C4 — Claim Inclusion in Claims Tree
    // =========================================================
    component claimSmt = SMTVerifier(claimMtpDepth);
    claimSmt.enabled   <== 1;
    claimSmt.fnc       <== 0;                   // 0 = inclusion
    claimSmt.root      <== claimsTreeRoot;
    claimSmt.key       <== claimHasher.leafHash;
    claimSmt.value     <== claimHasher.leafHash; // key == value by convention
    claimSmt.oldKey    <== 0;
    claimSmt.oldValue  <== 0;
    claimSmt.isOld0    <== 0;                   // 0 for inclusion (isOld0=1 would conflict with st_inew)
    for (var i = 0; i < claimMtpDepth; i++) {
        claimSmt.siblings[i] <== claimMtp[i];
    }

    // =========================================================
    // C5 — Claims Tree Root in Roots Tree
    // =========================================================
    component rootsSmt = SMTVerifier(rootsMtpDepth);
    rootsSmt.enabled   <== 1;
    rootsSmt.fnc       <== 0;
    rootsSmt.root      <== rootsTreeRoot;
    rootsSmt.key       <== claimsTreeRoot;
    rootsSmt.value     <== claimsTreeRoot;
    rootsSmt.oldKey    <== 0;
    rootsSmt.oldValue  <== 0;
    rootsSmt.isOld0    <== 0;
    for (var i = 0; i < rootsMtpDepth; i++) {
        rootsSmt.siblings[i] <== rootsMtp[i];
    }

    // =========================================================
    // C6 — Non-Revocation (SMT non-inclusion proof)
    // =========================================================
    component revSmt = SMTVerifier(revMtpDepth);
    revSmt.enabled   <== 1;
    revSmt.fnc       <== 1;                     // 1 = non-inclusion
    revSmt.root      <== revocationTreeRoot;
    revSmt.key       <== claimRevNonce;
    revSmt.value     <== 0;
    revSmt.oldKey    <== revMtpOldKey;
    revSmt.oldValue  <== revMtpOldValue;
    revSmt.isOld0    <== revMtpIsOld0;
    for (var i = 0; i < revMtpDepth; i++) {
        revSmt.siblings[i] <== revMtp[i];
    }

    // =========================================================
    // C7 — Issuer State Binding & Signature
    // =========================================================
    component stateHasher = Poseidon(3);
    stateHasher.inputs[0] <== claimsTreeRoot;
    stateHasher.inputs[1] <== revocationTreeRoot;
    stateHasher.inputs[2] <== rootsTreeRoot;
    stateHasher.out === issuerState;

    component eddsaVerifier = EdDSAPoseidonVerifier();
    eddsaVerifier.enabled <== 1;
    eddsaVerifier.Ax      <== issuerPubKeyAx;
    eddsaVerifier.Ay      <== issuerPubKeyAy;
    eddsaVerifier.R8x     <== issuerSigR8x;
    eddsaVerifier.R8y     <== issuerSigR8y;
    eddsaVerifier.S       <== issuerSigS;
    eddsaVerifier.M       <== issuerState;

    component issuerIdHasher = Poseidon(2);
    issuerIdHasher.inputs[0] <== issuerPubKeyAx;
    issuerIdHasher.inputs[1] <== issuerPubKeyAy;
    issuerIdHasher.out === issuerId;

    // =========================================================
    // C8 — Predicate Check
    // =========================================================
    component predicate = PredicateCheck(64);
    predicate.attributeValue <== claimAttributeValue;
    predicate.predicateType  <== predicateType;
    predicate.predicateValue <== predicateValue;
    predicate.valid          === 1;

    // =========================================================
    // C9 — Expiry Check: currentTimestamp <= claimExpiry
    // =========================================================
    component expiryCheck = LessEqThan(64);
    expiryCheck.in[0] <== currentTimestamp;
    expiryCheck.in[1] <== claimExpiry;
    expiryCheck.out   === 1;

    // =========================================================
    // C10 — Nullifier Output
    // =========================================================
    component nullifierComp = NullifierHasher();
    nullifierComp.nullifierSeed <== nullifierSeed;
    nullifierComp.contextId     <== contextId;
    nullifierHash <== nullifierComp.nullifierHash;
}

component main {public [
    issuerId,
    issuerState,
    requestedSchemaHash,
    requestedAttributeKey,
    predicateType,
    predicateValue,
    contextId,
    currentTimestamp
]} = CredentialAtomicQuery(20, 20, 20);
