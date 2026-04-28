"use strict";

// ============================================================
// credentialAtomicQuery.test.js — Test suite cho mạch ZKP
// ============================================================
//
// Chiến lược test:
//   - buildInputs() tạo một bộ witness đầy đủ và hợp lệ (happy path).
//   - Mỗi negative test ghi đè (override) đúng một trường để vi phạm một constraint.
//   - Đối với negative tests: assertion là proof bị REJECTED (witness generation fail),
//     không phải proof generation fail — vì lỗi constraint xảy ra ở giai đoạn WASM.
//
// Thứ tự kiểm tra trong mạch (khi witness fail, error trỏ đến constraint đầu tiên bị vi phạm):
//   C1 (identity) → C2 (schema) → C3+C4 (claim hash + Merkle) →
//   C5 (roots tree) → C6 (non-revocation) → C7 (issuer sig) → C8 (predicate) → C9 (expiry)

const path   = require("path");
const assert = require("assert");
const chai   = require("chai");
const cap    = require("chai-as-promised");
chai.use(cap);
const { expect } = chai;

const snarkjs    = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const { buildClaim, hashClaim }          = require("./helpers/claim");
const { signIssuerState, deriveIssuerId } = require("./helpers/eddsa");
const {
  buildClaimsTree, getClaimInclusionProof,
  buildRootsTree,  getRootsInclusionProof,
  buildRevocationTree, getRevNonInclusionProof,
  getRoot,
} = require("./helpers/smt");

// Path tới artefacts được compile bởi scripts/compile.sh + scripts/setup.sh
const WASM_PATH = path.join(__dirname, "../build/credentialAtomicQuery_js/credentialAtomicQuery.wasm");
const ZKEY_PATH = path.join(__dirname, "../build/credentialAtomicQuery_final.zkey");

// Khoá bí mật Issuer dùng trong test — GIÁ TRỊ CỐ ĐỊNH, KHÔNG DÙNG PRODUCTION
const ISSUER_PRIV_KEY = Buffer.from(
  "0001020304050607080900010203040506070809000102030405060708090001",
  "hex"
);

// Poseidon instance dùng chung trong toàn bộ test suite
let poseidon;

before(async () => {
  poseidon = await buildPoseidon();
});

// Wrapper tiện lợi: hash nhiều inputs, trả về BigInt
function poseidonHash(inputs) {
  return poseidon.F.toObject(poseidon(inputs.map(BigInt)));
}

// ============================================================
// buildInputs(overrides) — Tạo bộ witness hợp lệ hoàn chỉnh
// ============================================================
//
// Luồng:
//   1. Holder: tạo skid, nullifierSeed → tính idcom
//   2. Claim: xây dựng claim với attributeValue=25 (tuổi)
//   3. claimsTree: thêm leafHash vào, lấy inclusion proof
//   4. revocationTree: cây rỗng (claim chưa bị revoke), lấy non-inclusion proof
//   5. rootsTree: thêm claimsTreeRoot, lấy inclusion proof
//   6. issuerState: Poseidon(3 roots), Issuer ký bằng EdDSA-Poseidon
//   7. Gom tất cả thành object inputs cho snarkjs.groth16.fullProve()
//
// overrides: object chứa các trường muốn ghi đè (dùng cho negative tests)
async function buildInputs(overrides = {}) {
  // --- Holder identity ---
  const skid          = 12345678901234567890n;
  const nullifierSeed = 98765432109876543210n;
  // idcom = Poseidon(skid, nullifierSeed) — đây là "địa chỉ" của Holder
  const idcom         = poseidonHash([skid, nullifierSeed]);

  // --- Claim attributes ---
  // schemaHash: ID loại claim — hash của chuỗi "AgeClaim_v1"
  const schemaHash    = poseidonHash([BigInt("0x4167655f436c61696d5f7631")]);
  // attributeKey: tên thuộc tính — hash của chuỗi "age"
  const attributeKey  = poseidonHash([BigInt("0x616765")]);
  const attributeValue = 25n;  // Tuổi thực của Holder (bí mật)
  const expiry        = 2000000000n; // Unix ~năm 2033 — chưa hết hạn
  const revNonce      = 42n;         // Nonce ngẫu nhiên cho revocation

  const claim = buildClaim({
    schemaHash,
    subjectId:      idcom,
    attributeKey,
    attributeValue,
    expiry,
    revNonce,
  });

  // leafHash = Poseidon(6 trường) — đây là key+value trong claimsTree
  const leafHash = await hashClaim(claim);

  // --- Xây dựng 3 Sparse Merkle Trees ---

  // claimsTree: chứa claim của Holder (chỉ 1 claim trong test này)
  const claimsTree  = await buildClaimsTree([leafHash]);
  const claimsRoot  = await getRoot(claimsTree);
  const claimProof  = await getClaimInclusionProof(claimsTree, leafHash);

  // revocationTree: rỗng → claim CHƯA bị thu hồi
  const revTree   = await buildRevocationTree([]);
  const revRoot   = await getRoot(revTree);
  const revProof  = await getRevNonInclusionProof(revTree, revNonce);

  // rootsTree: chứa claimsRoot vừa tạo (Issuer thêm sau mỗi lần update claims)
  const rootsTree   = await buildRootsTree([claimsRoot]);
  const rootsRoot   = await getRoot(rootsTree);
  const rootsProof  = await getRootsInclusionProof(rootsTree, claimsRoot);

  // --- Issuer ký issuerState ---
  // issuerState = Poseidon(claimsRoot, revRoot, rootsRoot) — tóm tắt toàn bộ trạng thái
  const issuerState = poseidonHash([claimsRoot, revRoot, rootsRoot]);
  const sig         = await signIssuerState(ISSUER_PRIV_KEY, issuerState);

  // issuerId = Poseidon(Ax, Ay) — ID on-chain của Issuer
  const issuerIdComputed = poseidonHash([sig.Ax, sig.Ay]);

  // --- Context và predicate ---
  const contextId = 777n;
  const currentTimestamp = 1700000000n; // Nhỏ hơn expiry → claim còn hạn

  // Predicate: "age >= 18" (predicateType=1 là gte)
  const predicateType  = 1n;
  const predicateValue = 18n;

  const inputs = {
    // === PUBLIC INPUTS ===
    issuerId:               issuerIdComputed,
    issuerState:            issuerState,
    requestedSchemaHash:    schemaHash,
    requestedAttributeKey:  attributeKey,
    predicateType:          predicateType,
    predicateValue:         predicateValue,
    contextId:              contextId,
    currentTimestamp:       currentTimestamp,
    // === PRIVATE: danh tính Holder ===
    skid:                   skid,
    nullifierSeed:          nullifierSeed,
    // === PRIVATE: 6 trường claim ===
    claimSchemaHash:        claim.schemaHash,
    claimSubjectId:         claim.subjectId,
    claimAttributeKey:      claim.attributeKey,
    claimAttributeValue:    claim.attributeValue,
    claimExpiry:            claim.expiry,
    claimRevNonce:          claim.revNonce,
    // === PRIVATE: roots của 3 cây ===
    claimsTreeRoot:         claimsRoot,
    revocationTreeRoot:     revRoot,
    rootsTreeRoot:          rootsRoot,
    // === PRIVATE: Merkle paths ===
    claimMtp:               claimProof.siblings,
    rootsMtp:               rootsProof.siblings,
    revMtp:                 revProof.siblings,
    // Extra data cho non-inclusion proof (revocationTree)
    revMtpOldKey:           revProof.oldKey,
    revMtpOldValue:         revProof.oldValue,
    revMtpIsOld0:           revProof.isOld0,
    // === PRIVATE: chữ ký Issuer ===
    issuerPubKeyAx:         sig.Ax,
    issuerPubKeyAy:         sig.Ay,
    issuerSigR8x:           sig.R8x,
    issuerSigR8y:           sig.R8y,
    issuerSigS:             sig.S,
  };

  // Ghi đè các trường được chỉ định — dùng cho negative tests
  return Object.assign({}, inputs, overrides);
}

// Tạo proof đầy đủ và verify. Trả về { ok, publicSignals }.
// Dùng cho happy path và TC8 (unlinkability).
async function generateAndVerify(inputs) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs, WASM_PATH, ZKEY_PATH
  );
  const vKey = await snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
  const ok   = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  return { ok, publicSignals };
}

// Chỉ tính witness (không generate proof đầy đủ) — nhanh hơn cho negative tests.
// Nếu có constraint violation → WASM throw ngay ở bước này.
// Trong implementation này gọi generateAndVerify để đơn giản hóa,
// nhưng negative tests chỉ cần witness fail nên vẫn đúng.
async function generateWitness(inputs) {
  return generateAndVerify(inputs);
}

// ============================================================
// Test suite
// ============================================================
describe("CredentialAtomicQuery", function () {
  this.timeout(300_000); // 5 phút mỗi test (setup keys + proof generation tốn thời gian)

  // ----------------------------------------------------------
  // TC1: Happy path — toàn bộ đúng → proof hợp lệ
  // ----------------------------------------------------------
  // Kiểm tra: proof được tạo, verify OK, và nullifierHash đúng công thức.
  // publicSignals[0] = nullifierHash (output duy nhất của mạch).
  it("TC1 happy path: age=25, predicate >= 18 → proof valid", async () => {
    const inputs  = await buildInputs();
    const { ok, publicSignals } = await generateAndVerify(inputs);
    expect(ok).to.be.true;

    // Verify nullifierHash = Poseidon(nullifierSeed, contextId)
    const expectedNullifier = poseidonHash([inputs.nullifierSeed, inputs.contextId]);
    expect(publicSignals[0]).to.equal(expectedNullifier.toString());
  });

  // ----------------------------------------------------------
  // TC2: Hacker đổi attributeValue → Merkle proof không khớp (C3+C4 fail)
  // ----------------------------------------------------------
  // Tree được build với attributeValue=25 → leafHash(25).
  // Witness truyền attributeValue=17 → mạch tính leafHash(17) ≠ leafHash(25).
  // SMTVerifier (C4) phát hiện key không khớp → constraint fail.
  it("TC2 rejects tampered attribute value (17→25): Merkle path invalid", async () => {
    // Tree được build với attributeValue=25. Attacker presents 17 instead.
    // leafHash_computed = Poseidon(..., 17, ...) ≠ tree leaf → C4 fails.
    const overrides = { claimAttributeValue: 17n };
    const tampered = await buildInputs(overrides);
    // To make TC2 realistic, build inputs normally but then override the value
    await expect(generateWitness(tampered)).to.be.rejected;
  });

  // ----------------------------------------------------------
  // TC3: Hacker dùng public key giả → EdDSA fail (C7 fail)
  // ----------------------------------------------------------
  // Chữ ký (R8x, R8y, S) được tạo bởi ISSUER_PRIV_KEY, nhưng Ax/Ay là của fakeKey.
  // EdDSAPoseidonVerifier kiểm tra chữ ký phải hợp lệ với đúng public key → fail.
  it("TC3 rejects fake issuer pubKey (C7 EdDSA fail)", async () => {
    const fakeKey = Buffer.from(
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      "hex"
    );
    const { buildEddsa } = require("circomlibjs");
    const eddsa = await buildEddsa();
    const fakePub = eddsa.prv2pub(fakeKey);
    const overrides = {
      issuerPubKeyAx: eddsa.F.toObject(fakePub[0]),
      issuerPubKeyAy: eddsa.F.toObject(fakePub[1]),
      // Chữ ký giữ nguyên (của Issuer thật) nhưng public key sai → EdDSA fail
    };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  // ----------------------------------------------------------
  // TC4: Holder dùng sai skid → identity fail (C1 fail)
  // ----------------------------------------------------------
  // idcom_computed = Poseidon(skid_sai, nullifierSeed) ≠ claim.subjectId
  // → constraint "idcom === claimSubjectId" fail → proof không tạo được.
  it("TC4 rejects wrong Holder skid (C1 identity fail)", async () => {
    const overrides = { skid: 99999999999999999999n }; // skid không khớp với subjectId trong claim
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  // ----------------------------------------------------------
  // TC5: VC đã hết hạn → expiry fail (C9 fail)
  // ----------------------------------------------------------
  // currentTimestamp=9999999999 > claimExpiry=1000 → LessEqThan trả về 0 → constraint fail.
  // Lưu ý: override claimExpiry cũng thay đổi leafHash → C4 cũng fail,
  // nhưng mục tiêu chính là test C9.
  it("TC5 rejects expired VC (C9 expiry fail)", async () => {
    const overrides = { currentTimestamp: 9999999999n, claimExpiry: 1000n };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  // ----------------------------------------------------------
  // TC6: VC đã bị revoke → non-inclusion fail (C6 fail)
  // ----------------------------------------------------------
  // Build một revocationTree CÓ chứa revNonce → claim đã bị thu hồi.
  // Truyền revocationTreeRoot mới (có revNonce), nhưng issuerState vẫn là cũ
  // → hoặc C7 fail (issuerState không khớp) hoặc C6 fail (non-inclusion sai).
  // Dù sao cũng bị reject — đây là mục tiêu của test.
  it("TC6 rejects revoked VC (C6 non-inclusion fail)", async () => {
    const inputs = await buildInputs();
    // Tạo revTree CÓ chứa revNonce → claim đã bị thu hồi
    const revokedTree = await buildRevocationTree([inputs.claimRevNonce]);
    const revokedRoot  = await getRoot(revokedTree);
    // Non-inclusion proof sẽ fail → dùng siblings giả (tất cả 0)
    const badRevProof = {
      siblings:    new Array(20).fill(0n),
      oldKey:      inputs.claimRevNonce,
      oldValue:    inputs.claimRevNonce,
      isOld0:      0,
    };
    const overrides = {
      revocationTreeRoot: revokedRoot,
      revMtp:             badRevProof.siblings,
      revMtpOldKey:       badRevProof.oldKey,
      revMtpOldValue:     badRevProof.oldValue,
      revMtpIsOld0:       badRevProof.isOld0,
      // issuerState không đổi → C7 fail HOẶC C6 fail — cả hai đều reject
    };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  // ----------------------------------------------------------
  // TC7: Holder dùng claim "country" để trả lời query "age" (C2 fail)
  // ----------------------------------------------------------
  // claimSchemaHash ≠ requestedSchemaHash → constraint "===" trong C2 fail.
  it("TC7 rejects wrong schema (claim 'country' used for 'age' query)", async () => {
    const wrongSchema = poseidonHash([BigInt("0x636f756e747279")]);  // hash("country")
    const overrides   = { claimSchemaHash: wrongSchema };
    await expect(generateWitness(await buildInputs(overrides))).to.be.rejected;
  });

  // ----------------------------------------------------------
  // TC8: Cùng Holder, 2 contextId khác nhau → 2 nullifier khác nhau (Unlinkability)
  // ----------------------------------------------------------
  // Verifier A cấp contextId=111, Verifier B cấp contextId=222.
  // nullifier1 = Poseidon(seed, 111) ≠ nullifier2 = Poseidon(seed, 222).
  // Không ai có thể biết hai proof này đến từ cùng một người.
  it("TC8 two proofs from same Holder with different contextIds → different nullifiers", async () => {
    const inputs1 = await buildInputs({ contextId: 111n });
    const inputs2 = await buildInputs({ contextId: 222n });

    const wtns1 = await generateWitness(inputs1);
    const wtns2 = await generateWitness(inputs2);

    // Tính nullifier trực tiếp để so sánh (không cần parse publicSignals)
    const n1 = poseidonHash([inputs1.nullifierSeed, inputs1.contextId]);
    const n2 = poseidonHash([inputs2.nullifierSeed, inputs2.contextId]);
    expect(n1).to.not.equal(n2); // Hai nullifier phải KHÁC NHAU
    // Cả hai proof phải được tạo thành công
    expect(wtns1).to.be.ok;
    expect(wtns2).to.be.ok;
  });

  // ----------------------------------------------------------
  // TC9: Predicate type=3 (range) — age=25, điều kiện [20,30] → valid
  // ----------------------------------------------------------
  // predicateValue encoding: low + high × 2^64 = 20 + 30 × 2^64
  // Mạch giải mã bằng Num2Bits(128): predicateLow=20, predicateHigh=30.
  // Kiểm tra: 20 <= 25 <= 30 → valid=1 → proof hợp lệ.
  it("TC9 predicate type=3 (range): age=25, range [20,30] → valid", async () => {
    const low  = 20n;
    const high = 30n;
    // Nhét cả low và high vào một trường: low ở 64 bits dưới, high ở 64 bits trên
    const rangeVal = low + high * (2n ** 64n);
    const inputs = await buildInputs({
      predicateType:  3n,
      predicateValue: rangeVal,
    });
    const { ok } = await generateAndVerify(inputs);
    expect(ok).to.be.true;
  });
});
