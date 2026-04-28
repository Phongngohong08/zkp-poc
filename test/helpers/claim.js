"use strict";

// ============================================================
// helpers/claim.js — Tạo và hash claim object trong test
// ============================================================
//
// Một claim đại diện cho một thuộc tính của Holder (vd: tuổi, quốc tịch).
// Trong mạch, claim được "nén" thành một leafHash duy nhất bằng Poseidon(6 fields).
// leafHash này là key+value khi insert vào claimsTree của Issuer.
//
// Công thức (phải khớp chính xác với circuits/lib/claim.circom):
//   leafHash = Poseidon(schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce)

const { buildPoseidon } = require("circomlibjs");

// Cache Poseidon instance để không khởi tạo lại nhiều lần (khởi tạo khá chậm ~100ms)
let _poseidon = null;

async function getPoseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

// Tạo claim object từ các trường.
// Hàm này chỉ gom các trường lại — không validate, không hash.
function buildClaim({
  schemaHash,     // ID loại claim (vd Poseidon("AgeClaim_v1"))
  subjectId,      // idcom của Holder = Poseidon(skid, nullifierSeed)
  attributeKey,   // Tên thuộc tính (vd Poseidon("age"))
  attributeValue, // Giá trị (vd 25n cho tuổi 25)
  expiry,         // Unix timestamp hết hạn (vd 2000000000n = năm 2033)
  revNonce,       // Nonce chống thu hồi (Issuer thêm vào revTree khi revoke)
}) {
  return { schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce };
}

// Tính leafHash của claim — đây là giá trị được insert vào claimsTree.
// Thứ tự 6 inputs phải khớp CHÍNH XÁC với mạch Circom (claim.circom).
// Sai thứ tự → leafHash khác → Merkle proof (C4) không khớp → proof fail.
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
  return poseidon.F.toObject(h); // Chuyển về BigInt (thoát khỏi Montgomery form)
}

module.exports = { buildClaim, hashClaim };
