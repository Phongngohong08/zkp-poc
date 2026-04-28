pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// ============================================================
// C3 — Claim Leaf Hash Computation (Tính hash của một claim)
// ============================================================
//
// Mục đích:
//   Mỗi claim được lưu trong Sparse Merkle Tree (SMT) của Issuer dưới dạng một lá (leaf).
//   Để chứng minh claim có tồn tại trong cây, mạch cần tính lại hash của claim từ
//   các trường riêng lẻ, rồi dùng hash đó để verify Merkle proof (C4).
//
// Công thức:
//   leafHash = Poseidon(schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce)
//
// Ý nghĩa từng trường:
//   schemaHash    — ID của loại claim, ví dụ hash("AgeClaim_v1"). Ngăn lẫn lộn giữa
//                   các loại credential khác nhau (C2 đảm bảo schema đúng loại).
//   subjectId     — idcom của Holder (= Poseidon(skid, nullifierSeed)). Gắn claim với
//                   đúng chủ sở hữu (C1 đảm bảo Holder biết skid tương ứng).
//   attributeKey  — Tên thuộc tính (hash của chuỗi, vd hash("age")). Cho phép một
//                   credential chứa nhiều claim (mỗi attribute là một leaf riêng).
//   attributeValue — Giá trị thuộc tính (vd 25 cho tuổi). Đây là giá trị bí mật
//                   mà Holder chứng minh thoả mãn predicate mà không tiết lộ.
//   expiry        — Unix timestamp hết hạn. C9 kiểm tra currentTimestamp <= expiry.
//   revNonce      — Nonce dùng cho revocation tree. Issuer thêm revNonce vào
//                   revocation tree khi muốn thu hồi claim (C6 kiểm tra NON-inclusion).
//
// Tại sao hash tất cả 6 trường lại với nhau?
//   Nếu hacker thay đổi bất kỳ trường nào (vd tăng attributeValue), leafHash sẽ thay đổi
//   → Merkle proof (C4) sẽ không khớp → proof thất bại. Đây là cơ chế đảm bảo INTEGRITY.

template ClaimHasher() {
    // === Inputs — 6 trường cấu thành một claim ===
    signal input schemaHash;     // Hash của loại claim (vd Poseidon("AgeClaim_v1"))
    signal input subjectId;      // idcom của Holder
    signal input attributeKey;   // Hash của tên thuộc tính (vd Poseidon("age"))
    signal input attributeValue; // Giá trị thuộc tính (bí mật, chứng minh qua predicate)
    signal input expiry;         // Thời hạn hiệu lực (unix timestamp)
    signal input revNonce;       // Nonce chống thu hồi

    // === Output ===
    signal output leafHash;      // Hash duy nhất đại diện cho claim này trong SMT

    // Poseidon với 6 inputs — đây là chuẩn của circomlib cho multi-input hashing
    component hasher = Poseidon(6);
    hasher.inputs[0] <== schemaHash;
    hasher.inputs[1] <== subjectId;
    hasher.inputs[2] <== attributeKey;
    hasher.inputs[3] <== attributeValue;
    hasher.inputs[4] <== expiry;
    hasher.inputs[5] <== revNonce;

    leafHash <== hasher.out;
}
