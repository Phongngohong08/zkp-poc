pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

include "./lib/identity.circom";
include "./lib/claim.circom";
include "./lib/nullifier.circom";
include "./lib/predicate.circom";

// ============================================================
// CredentialAtomicQuery — Mạch ZKP Credential (Paradigm 2: SMT of Claims)
// ============================================================
//
// MỤC TIÊU:
//   Holder chứng minh họ có một claim hợp lệ từ Issuer được uỷ quyền,
//   và thuộc tính trong claim thoả mãn một điều kiện nghiệp vụ (vd: tuổi >= 18),
//   MÀ KHÔNG tiết lộ: danh tính Holder, giá trị thuộc tính, hay bất kỳ trường nào khác.
//
// 6 MỤC TIÊU BẢO MẬT:
//   1. Authenticity    — Claim phải được Issuer ký số (C7: EdDSA-Poseidon)
//   2. Integrity       — Không thể thay đổi bất kỳ trường nào trong claim (C3+C4: Merkle)
//   3. Ownership       — Chỉ đúng Holder mới tạo được proof (C1: identity commitment)
//   4. Non-revocation  — Claim chưa bị thu hồi (C6: SMT non-inclusion proof)
//   5. Replay protection — Proof không thể dùng lại (C10: nullifier theo contextId)
//   6. Unlinkability   — Hai proof từ cùng Holder tại 2 Verifier khác nhau không liên kết được
//
// KIẾN TRÚC 3 CÂY (iden3 style):
//
//   ┌─────────────────────────────────────────────────────┐
//   │                    IssuerState                       │
//   │        = Poseidon(Cl_R, Re_R, Ro_R)                 │
//   │         (được Issuer ký bằng EdDSA-BabyJubJub)      │
//   └───────────────────┬─────────────────────────────────┘
//                       │
//          ┌────────────┼────────────┐
//          ▼            ▼            ▼
//      claimsTree   revTree      rootsTree
//      (Cl_R)       (Re_R)       (Ro_R)
//      Chứa các     Chứa         Chứa lịch sử
//      claim đã     revNonce     các Cl_R cũ
//      phát hành    bị revoke    (snapshot audit)
//
// CÁC RÀNG BUỘC (C1-C10):
//   C1  — identity.circom:   Poseidon(skid, seed) == claim.subjectId
//   C2  — inline:            claim.schemaHash == requestedSchemaHash
//                            claim.attributeKey == requestedAttributeKey
//   C3  — claim.circom:      leafHash = Poseidon(6 claim fields)
//   C4  — SMTVerifier:       leafHash ∈ claimsTree (inclusion proof)
//   C5  — SMTVerifier:       claimsTreeRoot ∈ rootsTree (inclusion proof)
//   C6  — SMTVerifier:       revNonce ∉ revocationTree (NON-inclusion proof)
//   C7  — Poseidon + EdDSA:  issuerState = Poseidon(Cl_R, Re_R, Ro_R) và Issuer ký đúng
//                            issuerId = Poseidon(pubKeyAx, pubKeyAy)
//   C8  — predicate.circom:  attributeValue thoả mãn điều kiện (eq/gte/lte/range)
//   C9  — LessEqThan:        currentTimestamp <= claimExpiry
//   C10 — nullifier.circom:  nullifierHash = Poseidon(nullifierSeed, contextId)
//
// CONVENTION SMT (iden3 style):
//   claimsTree:      key = leafHash,        value = leafHash      (inclusion)
//   rootsTree:       key = claimsTreeRoot,  value = claimsTreeRoot (inclusion)
//   revocationTree:  key = revNonce,        value = revNonce       (non-inclusion)
//
// DEPTH = 20: Cây có thể chứa tối đa 2^20 ≈ 1 triệu lá — phù hợp cho POC.
// Thay bằng 32 khi deploy production (nhưng sẽ tăng ~4× constraints và proving time).

template CredentialAtomicQuery(claimMtpDepth, revMtpDepth, rootsMtpDepth) {

    // =========================================================
    // PUBLIC INPUTS — Verifier biết và kiểm tra các giá trị này
    // =========================================================
    signal input issuerId;               // Poseidon(pubKeyAx, pubKeyAy) — định danh Issuer on-chain
    signal input issuerState;            // Poseidon(Cl_R, Re_R, Ro_R) — trạng thái hiện tại của Issuer
    signal input requestedSchemaHash;    // Loại claim Verifier yêu cầu (vd hash("AgeClaim_v1"))
    signal input requestedAttributeKey;  // Tên thuộc tính (vd hash("age"))
    signal input predicateType;          // Loại so sánh: 0=eq, 1=gte, 2=lte, 3=range
    signal input predicateValue;         // Ngưỡng so sánh (vd 18 cho "tuổi >= 18")
    signal input contextId;              // ID phiên do Verifier cấp (chống replay)
    signal input currentTimestamp;       // Thời gian hiện tại (unix) để kiểm tra expiry

    // PUBLIC OUTPUT — Verifier dùng để lưu on-chain chống double-spend
    signal output nullifierHash;

    // =========================================================
    // PRIVATE INPUTS — Holder giữ bí mật, chỉ dùng trong mạch
    // =========================================================

    // --- Danh tính Holder ---
    signal input skid;           // Khoá bí mật của Holder
    signal input nullifierSeed;  // Seed ngẫu nhiên bí mật (tạo idcom và nullifier)

    // --- 6 trường của claim (Holder lấy từ VC do Issuer cấp) ---
    signal input claimSchemaHash;     // Phải == requestedSchemaHash (C2)
    signal input claimSubjectId;      // Phải == Poseidon(skid, nullifierSeed) (C1)
    signal input claimAttributeKey;   // Phải == requestedAttributeKey (C2)
    signal input claimAttributeValue; // Giá trị bí mật, kiểm tra qua predicate (C8)
    signal input claimExpiry;         // Hạn dùng (C9: currentTimestamp <= expiry)
    signal input claimRevNonce;       // Nonce chống thu hồi (C6: không có trong revTree)

    // --- Roots của 3 sub-trees (private nhưng bị ràng buộc với public issuerState qua C7) ---
    signal input claimsTreeRoot;      // Root của claims tree tại thời điểm claim được phát hành
    signal input revocationTreeRoot;  // Root của revocation tree hiện tại
    signal input rootsTreeRoot;       // Root của roots tree (lịch sử các claimsTreeRoot)

    // --- Merkle paths (siblings arrays) cho 3 SMT proofs ---
    signal input claimMtp[claimMtpDepth];  // C4: inclusion proof của leafHash trong claimsTree
    signal input rootsMtp[rootsMtpDepth];  // C5: inclusion proof của claimsTreeRoot trong rootsTree
    signal input revMtp[revMtpDepth];      // C6: non-inclusion proof của revNonce trong revTree

    // --- Extra data cho non-inclusion proof (iden3 SMTVerifier cần biết "lá kề") ---
    // Khi revNonce không có trong revTree, verifier cần biết leaf tại vị trí đó
    // (nếu cây rỗng tại đó: oldKey=0, oldValue=0, isOld0=1)
    signal input revMtpOldKey;    // Key của lá kề trong revTree (0 nếu không có)
    signal input revMtpOldValue;  // Value của lá kề (0 nếu không có)
    signal input revMtpIsOld0;    // 1 = không có lá kề (đường đi trống), 0 = có lá kề

    // --- Chữ ký EdDSA-Poseidon của Issuer trên issuerState ---
    signal input issuerPubKeyAx;  // Toạ độ x của public key Issuer (BabyJubJub point)
    signal input issuerPubKeyAy;  // Toạ độ y của public key Issuer
    signal input issuerSigR8x;    // Chữ ký R8.x
    signal input issuerSigR8y;    // Chữ ký R8.y
    signal input issuerSigS;      // Chữ ký S (scalar)

    // =========================================================
    // C1 — Identity Ownership
    // Chứng minh Holder biết skid ứng với subjectId trong claim.
    // Nếu Holder thử dùng VC của người khác → constraint fail.
    // =========================================================
    component identityCheck = IdentityOwnership();
    identityCheck.skid           <== skid;
    identityCheck.nullifierSeed  <== nullifierSeed;
    identityCheck.claimSubjectId <== claimSubjectId;

    // =========================================================
    // C2 — Schema & Attribute Key Match
    // Đảm bảo Holder không dùng claim "country" để trả lời query "age".
    // Đây là equality constraint đơn giản, không cần component riêng.
    // =========================================================
    claimSchemaHash   === requestedSchemaHash;
    claimAttributeKey === requestedAttributeKey;

    // =========================================================
    // C3 — Claim Leaf Hash
    // Tính leafHash từ 6 trường của claim. leafHash này sẽ được dùng
    // làm key+value khi verify Merkle inclusion proof (C4).
    // Bất kỳ thay đổi nào trong 6 trường → leafHash thay đổi → C4 fail.
    // =========================================================
    component claimHasher = ClaimHasher();
    claimHasher.schemaHash     <== claimSchemaHash;
    claimHasher.subjectId      <== claimSubjectId;
    claimHasher.attributeKey   <== claimAttributeKey;
    claimHasher.attributeValue <== claimAttributeValue;
    claimHasher.expiry         <== claimExpiry;
    claimHasher.revNonce       <== claimRevNonce;

    // =========================================================
    // C4 — Claim Inclusion in Claims Tree
    // Chứng minh claim này thực sự nằm trong cây claims của Issuer.
    // fnc=0: inclusion proof (khác fnc=1 là non-inclusion)
    // key == value == leafHash: convention iden3 (self-referencing leaf)
    // =========================================================
    component claimSmt = SMTVerifier(claimMtpDepth);
    claimSmt.enabled   <== 1;
    claimSmt.fnc       <== 0;                    // 0 = inclusion
    claimSmt.root      <== claimsTreeRoot;
    claimSmt.key       <== claimHasher.leafHash;
    claimSmt.value     <== claimHasher.leafHash;  // key == value theo convention iden3
    claimSmt.oldKey    <== 0;
    claimSmt.oldValue  <== 0;
    claimSmt.isOld0    <== 0;
    for (var i = 0; i < claimMtpDepth; i++) {
        claimSmt.siblings[i] <== claimMtp[i];
    }

    // =========================================================
    // C5 — Claims Tree Root in Roots Tree
    // Chứng minh claimsTreeRoot (snapshot tại thời điểm claim được phát hành)
    // là một root hợp lệ trong lịch sử của Issuer.
    // Điều này cho phép proof từ snapshot cũ vẫn hợp lệ kể cả khi Issuer
    // đã cập nhật claims tree sau đó (thêm claims mới).
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
    // C6 — Non-Revocation
    // Chứng minh revNonce của claim KHÔNG có trong revocation tree.
    // fnc=1: non-inclusion proof — ngược với C4 và C5.
    // oldKey/oldValue/isOld0: mô tả lá kề ở vị trí revNonce trong cây.
    //   - Cây rỗng tại đó: isOld0=1, oldKey=0, oldValue=0
    //   - Có lá khác tại đó: isOld0=0, oldKey=key_lá_đó, oldValue=value_lá_đó
    // =========================================================
    component revSmt = SMTVerifier(revMtpDepth);
    revSmt.enabled   <== 1;
    revSmt.fnc       <== 1;                      // 1 = non-inclusion
    revSmt.root      <== revocationTreeRoot;
    revSmt.key       <== claimRevNonce;
    revSmt.value     <== 0;                      // giá trị không quan trọng cho non-inclusion
    revSmt.oldKey    <== revMtpOldKey;
    revSmt.oldValue  <== revMtpOldValue;
    revSmt.isOld0    <== revMtpIsOld0;
    for (var i = 0; i < revMtpDepth; i++) {
        revSmt.siblings[i] <== revMtp[i];
    }

    // =========================================================
    // C7 — Issuer State Binding & Signature
    // Hai bước:
    //   (a) Tính lại issuerState từ 3 roots và so sánh với public input.
    //       → Ràng buộc 3 private roots vào public issuerState.
    //   (b) Verify chữ ký EdDSA-Poseidon của Issuer trên issuerState.
    //       → Đảm bảo issuerState được phát hành bởi đúng Issuer.
    //   (c) Kiểm tra issuerId = Poseidon(pubKeyAx, pubKeyAy).
    //       → Gắn public key vào ID on-chain của Issuer.
    // =========================================================

    // (a) Tính issuerState = Poseidon(claimsTreeRoot, revocationTreeRoot, rootsTreeRoot)
    component stateHasher = Poseidon(3);
    stateHasher.inputs[0] <== claimsTreeRoot;
    stateHasher.inputs[1] <== revocationTreeRoot;
    stateHasher.inputs[2] <== rootsTreeRoot;
    stateHasher.out === issuerState;  // Phải khớp với public input

    // (b) Verify chữ ký EdDSA-Poseidon
    // EdDSAPoseidonVerifier nhận message trực tiếp (không cần pre-hash thêm —
    // EdDSA-Poseidon đã hash message internally theo spec BabyJubJub).
    component eddsaVerifier = EdDSAPoseidonVerifier();
    eddsaVerifier.enabled <== 1;
    eddsaVerifier.Ax      <== issuerPubKeyAx;
    eddsaVerifier.Ay      <== issuerPubKeyAy;
    eddsaVerifier.R8x     <== issuerSigR8x;
    eddsaVerifier.R8y     <== issuerSigR8y;
    eddsaVerifier.S       <== issuerSigS;
    eddsaVerifier.M       <== issuerState;  // Message được ký là toàn bộ issuerState

    // (c) issuerId = Poseidon(pubKeyAx, pubKeyAy) — gắn key với ID on-chain
    component issuerIdHasher = Poseidon(2);
    issuerIdHasher.inputs[0] <== issuerPubKeyAx;
    issuerIdHasher.inputs[1] <== issuerPubKeyAy;
    issuerIdHasher.out === issuerId;

    // =========================================================
    // C8 — Predicate Check (Business Logic)
    // Kiểm tra attributeValue thoả mãn điều kiện Verifier yêu cầu.
    // Xem predicate.circom để hiểu chi tiết encoding và selector logic.
    // =========================================================
    component predicate = PredicateCheck(64);
    predicate.attributeValue <== claimAttributeValue;
    predicate.predicateType  <== predicateType;
    predicate.predicateValue <== predicateValue;
    predicate.valid          === 1;  // Buộc kết quả phải là "thoả mãn"

    // =========================================================
    // C9 — Expiry Check
    // Claim không được hết hạn tại thời điểm tạo proof.
    // LessEqThan(64): out = 1 khi in[0] <= in[1]
    // → currentTimestamp <= claimExpiry
    // =========================================================
    component expiryCheck = LessEqThan(64);
    expiryCheck.in[0] <== currentTimestamp;
    expiryCheck.in[1] <== claimExpiry;
    expiryCheck.out   === 1;  // Nếu claim đã expire → out = 0 → fail

    // =========================================================
    // C10 — Nullifier Output
    // nullifierHash = Poseidon(nullifierSeed, contextId)
    // Là PUBLIC OUTPUT duy nhất — Verifier on-chain lưu lại để chống replay.
    // nullifierSeed bí mật đảm bảo Verifier A và B không liên kết được 2 proof.
    // =========================================================
    component nullifierComp = NullifierHasher();
    nullifierComp.nullifierSeed <== nullifierSeed;
    nullifierComp.contextId     <== contextId;
    nullifierHash <== nullifierComp.nullifierHash;
}

// Khai báo public inputs và depth của 3 cây (đều 20 cho POC)
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
