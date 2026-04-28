pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// ============================================================
// C10 — Nullifier Computation (Tính nullifier chống replay)
// ============================================================
//
// Mục đích kép:
//   1. Chống replay attack: Verifier lưu nullifierHash vào smart contract sau khi
//      chấp nhận proof. Nếu cùng Holder thử nộp lại proof cho cùng contextId,
//      Verifier phát hiện nullifier đã tồn tại và từ chối.
//
//   2. Unlinkability: Hai proof từ cùng Holder nhưng khác contextId sẽ tạo ra
//      hai nullifierHash hoàn toàn khác nhau. Verifier A và Verifier B không thể
//      biết hai proof đến từ cùng một người.
//
// Công thức:
//   nullifierHash = Poseidon(nullifierSeed, contextId)
//
// contextId là gì?
//   ID phiên do Verifier cấp (vd hash của session token, request ID). Mỗi lần
//   Holder muốn prove, Verifier cấp một contextId mới → nullifier mới.
//
// Tại sao dùng nullifierSeed thay vì skid trực tiếp?
//   Nếu dùng skid, hai proof từ cùng Holder (dù khác contextId) sẽ có chung một
//   "gốc" dễ nhận ra. nullifierSeed là một giá trị bí mật riêng biệt của Holder,
//   không liên quan tới skid, đảm bảo unlinkability tốt hơn.
//
// nullifierHash là PUBLIC OUTPUT duy nhất của mạch.
//   Verifier on-chain biết nullifierHash nhưng không thể suy ra nullifierSeed hay
//   danh tính của Holder từ đó (tính một chiều của Poseidon).

template NullifierHasher() {
    // === Inputs ===
    signal input nullifierSeed; // Seed bí mật của Holder (private — không lộ ra ngoài)
    signal input contextId;     // ID phiên do Verifier cấp (public input)

    // === Output ===
    signal output nullifierHash; // Giá trị công khai, Verifier dùng để chống double-spend

    component hasher = Poseidon(2);
    hasher.inputs[0] <== nullifierSeed;
    hasher.inputs[1] <== contextId;

    nullifierHash <== hasher.out;
}
