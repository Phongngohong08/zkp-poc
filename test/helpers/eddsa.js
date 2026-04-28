"use strict";

// ============================================================
// helpers/eddsa.js — Ký issuerState bằng EdDSA-Poseidon
// ============================================================
//
// Issuer ký issuerState = Poseidon(claimsTreeRoot, revocationTreeRoot, rootsTreeRoot)
// bằng khoá BabyJubJub (đường cong elliptic dùng trong Circom/iden3).
//
// Tại sao EdDSA-Poseidon thay vì EdDSA-SHA512?
//   EdDSA thông thường dùng SHA-512 để hash message trước khi ký.
//   Trong ZK circuit, SHA-512 tốn ~20.000 constraints — quá đắt.
//   EdDSA-Poseidon thay SHA-512 bằng Poseidon (~250 constraints) → tiết kiệm 80×.
//
// BabyJubJub là gì?
//   Đường cong elliptic được thiết kế để hoạt động hiệu quả bên trong BN254
//   (đường cong mà Groth16 dùng). Public key là một điểm (Ax, Ay) trên BabyJubJub.
//
// Chữ ký EdDSA-Poseidon gồm 3 phần:
//   R8x, R8y — toạ độ của điểm R (commitment ngẫu nhiên)
//   S        — scalar (phần "chứng minh" của chữ ký)
//
// issuerId on-chain:
//   issuerId = Poseidon(Ax, Ay) — hash của public key, được publish trong DID Document.
//   Mạch verify issuerId === Poseidon(issuerPubKeyAx, issuerPubKeyAy) (C7c).

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

// Lấy public key BabyJubJub từ private key (32-byte Buffer).
// Trả về [Ax, Ay] dưới dạng field elements (Montgomery form).
async function getPubKey(privKeyBytes) {
  const eddsa = await getEddsa();
  return eddsa.prv2pub(privKeyBytes);
}

// Tính issuerId = Poseidon(pubKeyAx, pubKeyAy).
// pubKey là mảng [Ax, Ay] từ prv2pub — cần chuyển sang BigInt trước khi hash.
async function deriveIssuerId(pubKey) {
  const eddsa = await getEddsa();
  const poseidon = await getPoseidon();
  const Ax = eddsa.F.toObject(pubKey[0]); // Thoát khỏi Montgomery form → BigInt
  const Ay = eddsa.F.toObject(pubKey[1]);
  const h = poseidon([Ax, Ay]);
  return poseidon.F.toObject(h);
}

// Ký issuerState và trả về tất cả giá trị cần truyền vào mạch.
//
// privKeyBytes: Buffer 32 bytes (trong test dùng giá trị cố định, KHÔNG dùng trong production).
// issuerState:  BigInt — Poseidon(claimsRoot, revRoot, rootsRoot).
//
// Returns:
//   Ax, Ay  — public key (dùng cho issuerId và EdDSA verification)
//   R8x, R8y, S — 3 phần của chữ ký EdDSA-Poseidon
async function signIssuerState(privKeyBytes, issuerState) {
  const eddsa = await getEddsa();

  // Chuyển issuerState về field element để ký
  const msg = eddsa.F.e(BigInt(issuerState));

  // signPoseidon: ký bằng Poseidon hash (khác với signMiMC hay signPedersen)
  const sig = eddsa.signPoseidon(privKeyBytes, msg);

  return {
    // Public key — Issuer publish on-chain
    Ax:  eddsa.F.toObject(eddsa.prv2pub(privKeyBytes)[0]),
    Ay:  eddsa.F.toObject(eddsa.prv2pub(privKeyBytes)[1]),
    // Chữ ký
    R8x: eddsa.F.toObject(sig.R8[0]),
    R8y: eddsa.F.toObject(sig.R8[1]),
    S:   sig.S, // Scalar — đã là BigInt, không cần chuyển
  };
}

module.exports = { getPubKey, deriveIssuerId, signIssuerState };
