"use strict";

const {
  Merkletree,
  InMemoryDB,
  circomSiblingsFromSiblings,
} = require("@iden3/js-merkletree");

const DEPTH = 20;

// Create an in-memory SMT of the given depth.
async function newTree() {
  const db = new InMemoryDB(new Uint8Array());
  return new Merkletree(db, true, DEPTH);
}

// Convert a circom-padded siblings array (Hash[]) → BigInt[].
function siblingsAsBigInt(siblings) {
  return siblings.map((s) => s.bigInt());
}

// Build the claims tree from an array of leafHash bigints.
// Convention: key = leafHash, value = leafHash.
async function buildClaimsTree(leafHashes) {
  const tree = await newTree();
  for (const lh of leafHashes) {
    await tree.add(BigInt(lh), BigInt(lh));
  }
  return tree;
}

// Get an inclusion proof for a claim leaf.
// Returns { siblings: BigInt[20] }
async function getClaimInclusionProof(tree, leafHash) {
  const { proof } = await tree.generateProof(BigInt(leafHash));
  if (!proof.existence) throw new Error("Claim not found in claims tree");
  const siblings = siblingsAsBigInt(circomSiblingsFromSiblings(proof.siblings, DEPTH));
  return { siblings };
}

// Build the roots tree from an array of historical claimsTreeRoots (bigints).
// Convention: key = root, value = root.
async function buildRootsTree(claimsTreeRoots) {
  const tree = await newTree();
  for (const r of claimsTreeRoots) {
    await tree.add(BigInt(r), BigInt(r));
  }
  return tree;
}

// Get an inclusion proof for a claimsTreeRoot.
async function getRootsInclusionProof(tree, claimsTreeRoot) {
  const { proof } = await tree.generateProof(BigInt(claimsTreeRoot));
  if (!proof.existence) throw new Error("Root not found in roots tree");
  const siblings = siblingsAsBigInt(circomSiblingsFromSiblings(proof.siblings, DEPTH));
  return { siblings };
}

// Build the revocation tree from an array of revokedNonces (bigints).
async function buildRevocationTree(revokedNonces) {
  const tree = await newTree();
  for (const n of revokedNonces) {
    await tree.add(BigInt(n), BigInt(n));
  }
  return tree;
}

// Get a non-inclusion proof for a revNonce (proves it is NOT in the tree).
// Returns { siblings: BigInt[20], oldKey: BigInt, oldValue: BigInt, isOld0: number }
async function getRevNonInclusionProof(tree, revNonce) {
  const { proof } = await tree.generateProof(BigInt(revNonce));
  if (proof.existence) throw new Error("revNonce IS in the revocation tree (claim is revoked)");

  const siblings = siblingsAsBigInt(circomSiblingsFromSiblings(proof.siblings, DEPTH));

  let oldKey = 0n;
  let oldValue = 0n;
  let isOld0 = 1; // 1 = no adjacent leaf (empty path)

  if (proof.nodeAux) {
    oldKey   = proof.nodeAux.key.bigInt();
    oldValue = proof.nodeAux.value.bigInt();
    isOld0   = 0;
  }

  return { siblings, oldKey, oldValue, isOld0 };
}

// Helper: get BigInt root from a tree.
async function getRoot(tree) {
  const root = await tree.root();
  return root.bigInt();
}

module.exports = {
  buildClaimsTree,
  getClaimInclusionProof,
  buildRootsTree,
  getRootsInclusionProof,
  buildRevocationTree,
  getRevNonInclusionProof,
  getRoot,
};
