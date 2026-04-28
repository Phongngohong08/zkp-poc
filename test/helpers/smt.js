"use strict";

// ============================================================
// helpers/smt.js — Xây dựng Sparse Merkle Tree cho tests
// ============================================================
//
// Mỗi Issuer duy trì 3 SMT độc lập:
//   1. claimsTree:      chứa tất cả claims đã phát hành (key = value = leafHash)
//   2. revocationTree:  chứa revNonce của claims đã thu hồi (key = value = revNonce)
//   3. rootsTree:       chứa lịch sử các claimsTreeRoot (key = value = root)
//
// Thư viện: @iden3/js-merkletree — cùng implementation với circomlib SMTVerifier,
// đảm bảo hash function và leaf convention khớp với mạch Circom.
//
// Mỗi proof trả về `siblings`: mảng BigInt độ dài DEPTH.
// Các phần tử bằng 0 nghĩa là không có lá tại node đó (đường trống).

const {
  Merkletree,
  InMemoryDB,
  circomSiblingsFromSiblings,
} = require("@iden3/js-merkletree");

// Depth = 20 → cây có thể chứa tối đa 2^20 ≈ 1 triệu lá.
// Phải khớp với tham số claimMtpDepth/revMtpDepth/rootsMtpDepth trong mạch.
const DEPTH = 20;

// Tạo một SMT rỗng, lưu trong bộ nhớ (không persist).
async function newTree() {
  const db = new InMemoryDB(new Uint8Array());
  return new Merkletree(db, true, DEPTH);
}

// Chuyển mảng siblings từ Hash[] (đối tượng của thư viện) sang BigInt[].
// circomSiblingsFromSiblings đã padding đủ DEPTH phần tử (0n cho slot trống).
function siblingsAsBigInt(siblings) {
  return siblings.map((s) => s.bigInt());
}

// ---- claimsTree ----
// Convention iden3: key = leafHash, value = leafHash (self-referencing).
// Khi có nhiều claims, mỗi leafHash là một lá riêng.
async function buildClaimsTree(leafHashes) {
  const tree = await newTree();
  for (const lh of leafHashes) {
    await tree.add(BigInt(lh), BigInt(lh));
  }
  return tree;
}

// Lấy inclusion proof cho một claim (C4 trong mạch).
// Ném lỗi nếu leafHash không có trong cây — test setup sai.
async function getClaimInclusionProof(tree, leafHash) {
  const { proof } = await tree.generateProof(BigInt(leafHash));
  if (!proof.existence) throw new Error("Claim not found in claims tree");
  const siblings = siblingsAsBigInt(circomSiblingsFromSiblings(proof.siblings, DEPTH));
  return { siblings };
}

// ---- rootsTree ----
// Convention iden3: key = claimsTreeRoot, value = claimsTreeRoot.
// Issuer thêm mỗi claimsTreeRoot vào đây sau mỗi lần update claims tree.
// Cho phép verify proof từ snapshot cũ (historical root).
async function buildRootsTree(claimsTreeRoots) {
  const tree = await newTree();
  for (const r of claimsTreeRoots) {
    await tree.add(BigInt(r), BigInt(r));
  }
  return tree;
}

// Lấy inclusion proof cho một claimsTreeRoot (C5 trong mạch).
async function getRootsInclusionProof(tree, claimsTreeRoot) {
  const { proof } = await tree.generateProof(BigInt(claimsTreeRoot));
  if (!proof.existence) throw new Error("Root not found in roots tree");
  const siblings = siblingsAsBigInt(circomSiblingsFromSiblings(proof.siblings, DEPTH));
  return { siblings };
}

// ---- revocationTree ----
// Convention iden3: key = revNonce, value = revNonce.
// Issuer thêm revNonce khi muốn thu hồi một claim.
// Test happy path: cây rỗng (không có nonce nào bị thu hồi).
async function buildRevocationTree(revokedNonces) {
  const tree = await newTree();
  for (const n of revokedNonces) {
    await tree.add(BigInt(n), BigInt(n));
  }
  return tree;
}

// Lấy NON-inclusion proof cho revNonce (C6 trong mạch).
// Chứng minh revNonce KHÔNG có trong cây → claim chưa bị thu hồi.
//
// SMTVerifier (iden3) cần 4 giá trị cho non-inclusion:
//   siblings: mảng anh em trên đường đi từ root đến vị trí revNonce
//   oldKey:   key của lá hiện có tại vị trí đó (nếu có)
//   oldValue: value của lá đó
//   isOld0:   1 = vị trí trống (không có lá nào), 0 = có lá khác tại đó
//
// Ném lỗi nếu revNonce đã có trong cây (claim đã bị revoke → test setup sai).
async function getRevNonInclusionProof(tree, revNonce) {
  const { proof } = await tree.generateProof(BigInt(revNonce));
  if (proof.existence) throw new Error("revNonce IS in the revocation tree (claim is revoked)");

  const siblings = siblingsAsBigInt(circomSiblingsFromSiblings(proof.siblings, DEPTH));

  // Mặc định: vị trí trống (cây rỗng hoặc không có lá tại đường đi này)
  let oldKey = 0n;
  let oldValue = 0n;
  let isOld0 = 1; // 1 = "is old leaf a zero leaf?" → có nghĩa là không có lá nào

  // Nếu có lá kề tại đó (cây có leaf khác ở vị trí gần revNonce)
  if (proof.nodeAux) {
    oldKey   = proof.nodeAux.key.bigInt();
    oldValue = proof.nodeAux.value.bigInt();
    isOld0   = 0;
  }

  return { siblings, oldKey, oldValue, isOld0 };
}

// Lấy root của cây dưới dạng BigInt.
// Cây rỗng có root = 0 (hash của 2 node rỗng trong iden3 SMT).
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
