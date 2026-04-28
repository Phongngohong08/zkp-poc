pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// ============================================================
// C1 — Identity Ownership (Chứng minh quyền sở hữu danh tính)
// ============================================================
//
// Mục đích:
//   Holder phải chứng minh rằng họ biết khoá bí mật (skid) tương ứng
//   với subjectId được ghi trong claim. Nếu Holder không có skid đúng,
//   họ không thể tạo ra proof hợp lệ — ngăn chặn việc dùng VC của người khác.
//
// Cách hoạt động:
//   1. Tính idcom = Poseidon(skid, nullifierSeed)  [trong mạch, không lộ ra ngoài]
//   2. Ép buộc idcom === claim.subjectId            [constraint]
//
// Tại sao dùng Poseidon thay vì hash thông thường?
//   Poseidon được thiết kế đặc biệt để hiệu quả trong mạch ZK (ít constraints hơn
//   SHA-256 khoảng 50×), đồng thời vẫn đảm bảo tính chất one-way và collision-resistant.
//
// nullifierSeed đóng vai trò gì?
//   Nó là một giá trị ngẫu nhiên bí mật của Holder. Việc tách skid và nullifierSeed
//   cho phép:
//   - nullifierSeed được dùng để tính nullifierHash (C10) mà không tiết lộ skid
//   - Issuer chỉ cần biết idcom (= commitment) để phát hành claim, không cần biết skid

template IdentityOwnership() {
    // === Inputs ===
    signal input skid;           // Khoá bí mật của Holder (private, không bao giờ lộ ra)
    signal input nullifierSeed;  // Seed ngẫu nhiên bí mật dùng cho idcom và nullifier
    signal input claimSubjectId; // subjectId được ghi trong claim (cũng là idcom)

    // === Output ===
    signal output idcom;         // Commitment của danh tính, bằng Poseidon(skid, nullifierSeed)

    // Tính idcom bằng hàm Poseidon 2 inputs
    component hasher = Poseidon(2);
    hasher.inputs[0] <== skid;
    hasher.inputs[1] <== nullifierSeed;

    idcom <== hasher.out;

    // Ràng buộc: idcom tính được phải khớp với subjectId trong claim.
    // Nếu Holder dùng sai skid hoặc nullifierSeed → constraint này fail → proof không tạo được.
    idcom === claimSubjectId;
}
