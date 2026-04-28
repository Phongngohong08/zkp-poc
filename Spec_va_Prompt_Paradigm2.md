# Đặc tả Mạch ZKP — Paradigm 2 (SMT of Claims)

**Stack:** Circom 2.x + SnarkJS + circomlib + circomlib-matrix
**Curve / Backend:** BN254 + Groth16 (hoặc PLONK qua snarkjs)
**Phong cách:** Iden3 / Polygon ID Claim Tree
**Phạm vi:** Chỉ mạch ZKP (circuit). Không bao gồm Issuer/Holder/Verifier services.

---

## 1. Mục tiêu của mạch

Mạch chứng minh rằng Holder sở hữu một **claim hợp lệ** được phát hành bởi một Issuer được uỷ quyền, và một thuộc tính cụ thể trong claim đó thoả mãn một **business predicate** (ví dụ: `age ≥ 18`), MÀ KHÔNG tiết lộ:

- Định danh của Holder
- Giá trị thuộc tính
- Các thuộc tính khác trong cùng credential

**Mạch đảm bảo (security goals):**

1. **Authenticity** — Claim phải được Issuer ký số.
2. **Integrity** — Hacker không thể thay đổi giá trị thuộc tính.
3. **Ownership** — Người tạo proof thực sự sở hữu định danh tương ứng.
4. **Non-revocation** — Credential chưa bị thu hồi.
5. **Replay protection** — Sinh nullifier theo context.
6. **Unlinkability** — Hai proof từ cùng Holder ở 2 Verifier khác nhau không thể bị liên kết.

---

## 2. Mô hình dữ liệu

### 2.1. Claim structure

Mỗi **claim** là một đơn vị thông tin về Holder. Một credential gồm nhiều claims (mỗi attribute = 1 claim).

```
claim = {
  schemaHash:  Felt   // ID của loại claim (ví dụ: "AgeClaim_v1")
  subjectId:   Felt   // idcom của Holder
  attributeKey: Felt  // tên thuộc tính (hash của "age", "country", ...)
  attributeValue: Felt // giá trị
  expiry:      Felt   // unix timestamp
  revNonce:    Felt   // nonce dùng cho revocation tree
}
```

**Hashing claim thành leaf của SMT:**
```
leafHash = Poseidon(schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce)
```

### 2.2. Cấu trúc cây của Issuer

Issuer duy trì một **State Tree** chứa Merkle root của 3 sub-trees:

```
IssuerState = Poseidon(claimsTreeRoot, revocationTreeRoot, rootsTreeRoot)
```

- **claimsTreeRoot (Cl_R):** SMT chứa tất cả claims đã phát hành. Leaf = `leafHash`.
- **revocationTreeRoot (Re_R):** SMT chứa revNonce của các claims đã bị thu hồi.
- **rootsTreeRoot (Ro_R):** SMT chứa lịch sử các `claimsTreeRoot` cũ (cho phép verify proof cũ).

Issuer ký `IssuerState` bằng EdDSA-BabyJubJub. Public key + chữ ký được publish qua DID Document on-chain.

### 2.3. Holder identity

```
skid:           Felt (private)        // khoá bí mật của Holder
nullifierSeed:  Felt (private)        // seed cho nullifier
idcom:          Felt = Poseidon(skid, nullifierSeed)   // public commitment
```

`idcom` được dùng làm `subjectId` trong các claim mà Issuer phát hành.

---

## 3. Public và Private Inputs của mạch

### 3.1. Public inputs (Verifier biết)

| Tên | Kiểu | Ý nghĩa |
|-----|------|---------|
| `issuerId` | Felt | Hash của public key Issuer (anchor on-chain) |
| `issuerState` | Felt | Root state hiện tại của Issuer |
| `requestedSchemaHash` | Felt | Loại claim đang yêu cầu (vd "AgeClaim_v1") |
| `requestedAttributeKey` | Felt | Tên thuộc tính (vd hash("age")) |
| `predicateType` | Felt | 0 = equal, 1 = greater, 2 = less, 3 = range, ... |
| `predicateValue` | Felt | Giá trị so sánh (vd 18) |
| `contextId` | Felt | ID của phiên Verifier (chống replay) |
| `nullifierHash` | Felt | Output: nullifier cho session này |
| `currentTimestamp` | Felt | Thời gian hiện tại (kiểm tra expiry) |

### 3.2. Private inputs (Holder giữ)

| Tên | Kiểu | Ý nghĩa |
|-----|------|---------|
| `skid` | Felt | Khoá bí mật |
| `nullifierSeed` | Felt | Seed cho idcom |
| `claim.schemaHash` | Felt | Phải == requestedSchemaHash |
| `claim.subjectId` | Felt | Phải == idcom |
| `claim.attributeKey` | Felt | Phải == requestedAttributeKey |
| `claim.attributeValue` | Felt | Witness cho predicate |
| `claim.expiry` | Felt | |
| `claim.revNonce` | Felt | |
| `claimsTreeRoot` | Felt | Root tại thời điểm claim được phát hành |
| `revocationTreeRoot` | Felt | Revocation root |
| `rootsTreeRoot` | Felt | Roots tree root |
| `claimMtp[depth]` | Felt[] | Merkle path inclusion của claim trong claimsTree |
| `revMtp[depth]` | Felt[] | Merkle path NON-inclusion của revNonce trong revocationTree |
| `rootsMtp[depth]` | Felt[] | Merkle path inclusion của claimsTreeRoot trong rootsTree |
| `issuerSignatureR8x, R8y, S` | Felt | Chữ ký EdDSA của Issuer trên `issuerState` |
| `issuerPubKeyAx, Ay` | Felt | Public key Issuer (BabyJubJub point) |

---

## 4. Các ràng buộc (Constraints)

Mạch thực thi **8 nhóm ràng buộc** liên kết với nhau:

### C1 — Identity Ownership
```
idcom_computed = Poseidon(skid, nullifierSeed)
idcom_computed === claim.subjectId
```
**Ý nghĩa:** Holder thực sự sở hữu `skid` ứng với `subjectId` trong claim.

### C2 — Schema Match
```
claim.schemaHash === requestedSchemaHash
claim.attributeKey === requestedAttributeKey
```
**Ý nghĩa:** Claim được dùng đúng là loại Verifier yêu cầu, không phải claim khác.

### C3 — Claim Hash Computation
```
leafHash = Poseidon(
  claim.schemaHash,
  claim.subjectId,
  claim.attributeKey,
  claim.attributeValue,
  claim.expiry,
  claim.revNonce
)
```

### C4 — Claim Inclusion in Claims Tree
```
SMTVerifier(
  root      = claimsTreeRoot,
  leaf      = leafHash,
  siblings  = claimMtp,
  inclusion = true
) === true
```
**Ý nghĩa:** Claim này thực sự nằm trong cây claims của Issuer.

### C5 — Claims Tree Root in Roots Tree
```
SMTVerifier(
  root      = rootsTreeRoot,
  leaf      = claimsTreeRoot,
  siblings  = rootsMtp,
  inclusion = true
) === true
```
**Ý nghĩa:** `claimsTreeRoot` là một root hợp lệ trong lịch sử của Issuer. Cho phép proof từ snapshot cũ vẫn hợp lệ nếu Issuer chưa "vô hiệu hoá" snapshot đó.

### C6 — Non-Revocation
```
SMTVerifier(
  root      = revocationTreeRoot,
  leaf      = claim.revNonce,
  siblings  = revMtp,
  inclusion = false   // NON-inclusion proof
) === true
```
**Ý nghĩa:** `revNonce` của claim này KHÔNG nằm trong revocation tree → claim chưa bị thu hồi.

### C7 — Issuer State Binding & Signature
```
issuerState_computed = Poseidon(claimsTreeRoot, revocationTreeRoot, rootsTreeRoot)
issuerState_computed === issuerState

EdDSAPoseidonVerifier(
  pubKey     = (issuerPubKeyAx, issuerPubKeyAy),
  signature  = (R8x, R8y, S),
  message    = issuerState
) === true

issuerId === Poseidon(issuerPubKeyAx, issuerPubKeyAy)
```
**Ý nghĩa:** Toàn bộ trạng thái cây của Issuer được ký số → không thể giả mạo cây hoặc chèn claim giả.

### C8 — Predicate (Business Logic)
Tuỳ theo `predicateType`:
- **0 (equal):** `claim.attributeValue === predicateValue`
- **1 (greater-or-equal):** `claim.attributeValue ≥ predicateValue` qua `LessEqThan(64)` chip
- **2 (less-or-equal):** `claim.attributeValue ≤ predicateValue`
- **3 (range):** chia `predicateValue` thành 2 felts (low, high) và check cả hai chiều

**Lưu ý:** Comparator của circomlib (`LessThan`, `GreaterThan`) yêu cầu input phải fit trong N bits → phải làm range check trước.

### C9 — Expiry Check
```
LessEqThan(currentTimestamp, claim.expiry) === 1
```

### C10 — Nullifier Computation (Public Output)
```
nullifierHash_computed = Poseidon(nullifierSeed, contextId)
nullifierHash_computed === nullifierHash
```
**Ý nghĩa:** Mạch ép buộc `nullifierHash` được tính đúng. Verifier on-chain lưu `nullifierHash` để chống double-spend trong cùng context.

---

## 5. Kiến trúc file circuit

```
circuits/
├── credentialAtomicQuery.circom    // Top-level component
├── lib/
│   ├── identity.circom             // C1 — idcom check
│   ├── claim.circom                // C3 — claim leaf hash
│   ├── smtVerifier.circom          // C4, C5, C6 — SMT proofs (dùng circomlib/smt/)
│   ├── issuerSignature.circom      // C7 — EdDSA verify
│   ├── predicate.circom            // C8 — query operators
│   └── nullifier.circom            // C10 — nullifier
└── test/
    ├── credentialAtomicQuery.test.js
    └── helpers.js
```

**Top-level template (pseudo):**
```circom
template CredentialAtomicQuery(claimMtpDepth, revMtpDepth, rootsMtpDepth) {
    // === Public ===
    signal input issuerId;
    signal input issuerState;
    signal input requestedSchemaHash;
    signal input requestedAttributeKey;
    signal input predicateType;
    signal input predicateValue;
    signal input contextId;
    signal input currentTimestamp;
    signal output nullifierHash;

    // === Private ===
    signal input skid;
    signal input nullifierSeed;
    signal input claimSchemaHash;
    signal input claimSubjectId;
    signal input claimAttributeKey;
    signal input claimAttributeValue;
    signal input claimExpiry;
    signal input claimRevNonce;
    signal input claimsTreeRoot;
    signal input revocationTreeRoot;
    signal input rootsTreeRoot;
    signal input claimMtp[claimMtpDepth];
    signal input revMtp[revMtpDepth];
    signal input rootsMtp[rootsMtpDepth];
    signal input issuerPubKeyAx;
    signal input issuerPubKeyAy;
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    // === Wiring components C1...C10 ===
    // (xem section 4)
}

component main {public [
    issuerId, issuerState, requestedSchemaHash, requestedAttributeKey,
    predicateType, predicateValue, contextId, currentTimestamp
]} = CredentialAtomicQuery(32, 32, 32);
```

---

## 6. Các thư viện circomlib cần dùng

| Component | Thư viện |
|-----------|----------|
| Poseidon hash | `circomlib/circuits/poseidon.circom` |
| EdDSA Poseidon verify | `circomlib/circuits/eddsaposeidon.circom` |
| SMT verifier | `circomlib/circuits/smt/smtverifier.circom` |
| Comparators | `circomlib/circuits/comparators.circom` (`LessEqThan`, `GreaterThan`, ...) |
| Bit decomposition | `circomlib/circuits/bitify.circom` (`Num2Bits`) |
| Mux | `circomlib/circuits/mux1.circom`, `mux4.circom` |

---

## 7. Test plan

| Test case | Kết quả mong đợi |
|-----------|------------------|
| Happy path: VC hợp lệ, age=25, predicate "≥18" | Proof generated, verifies OK |
| Hacker đổi `claimAttributeValue` 17 → 25 | C4 fail (Merkle path không khớp) |
| Hacker tự tạo VC mới với pubKey giả | C7 EdDSA verify fail |
| Holder dùng VC của người khác (sai skid) | C1 fail |
| VC đã expire | C9 fail |
| VC đã bị revoke | C6 fail |
| Holder thử dùng claim "country" cho query "age" | C2 fail |
| Replay proof cùng contextId | Verifier on-chain reject (nullifier đã tồn tại) |
| Same Holder, 2 contextId khác nhau | 2 nullifierHash khác nhau → unlinkable |

---

## 8. Ước tính chi phí (BN254 + Groth16)

| Thành phần | ~Constraints |
|------------|-------------:|
| 1× Poseidon (6 inputs) | ~250 |
| EdDSA Poseidon verify | ~4,000 |
| SMTVerifier depth 32 (×3) | ~30,000 × 3 = 90,000 |
| Comparators (3-4 cái) | ~500 |
| Identity + nullifier | ~500 |
| **Tổng** | **~95,000-105,000** |

→ Proving time: ~3-8 giây trên laptop, ~15-30 giây trên mobile.
→ Groth16 proof size: 256 bytes.
→ Solidity verifier gas: ~250k.

---

## 9. Những điểm KHÔNG nằm trong mạch (out-of-scope của spec này)

- Issuer service (cách build SMT, ký state)
- Holder wallet (lưu VC, build witness)
- Verifier service (tạo query request)
- Smart contract verifier (deploy, kiểm nullifier set)
- DID resolution

→ Có thể đặc tả trong tài liệu riêng nếu cần.

# Prompt cho Coding Agent — Triển khai Mạch ZKP Paradigm 2

> Copy toàn bộ block dưới đây và paste vào Claude Code, Cursor, hoặc bất kỳ coding agent nào. Đính kèm file `SPEC_Circuit_Paradigm2.md` làm context.

---

## PROMPT BẮT ĐẦU TỪ ĐÂY

Bạn là một kỹ sư ZK chuyên về Circom và hệ sinh thái Iden3/Polygon ID. Hãy triển khai một mạch ZKP credential atomic query theo đặc tả đính kèm (`SPEC_Circuit_Paradigm2.md`).

### Yêu cầu kỹ thuật

**Stack:**
- Circom 2.1.x
- circomlib (https://github.com/iden3/circomlib)
- snarkjs latest
- Groth16 backend, BN254 curve
- Node.js test với mocha + chai
- circomlibjs (cho hashing trong test)

**Project structure cần tạo:**

```
zkid-circuit/
├── circuits/
│   ├── credentialAtomicQuery.circom    # Top-level
│   ├── lib/
│   │   ├── identity.circom             # idcom = Poseidon(skid, nullifierSeed)
│   │   ├── claim.circom                # leafHash từ 6 fields
│   │   ├── predicate.circom            # query operators (eq, gte, lte, range)
│   │   └── nullifier.circom            # Poseidon(seed, contextId)
├── test/
│   ├── credentialAtomicQuery.test.js   # 9 test cases
│   ├── helpers/
│   │   ├── smt.js                      # Build SMT, generate proofs
│   │   ├── claim.js                    # Build claim object, hash
│   │   └── eddsa.js                    # Sign issuer state
│   └── fixtures/
│       └── happyPath.json              # Sample valid inputs
├── scripts/
│   ├── compile.sh                      # circom compile
│   ├── setup.sh                        # powers of tau + zkey
│   └── prove.sh                        # generate proof
├── package.json
├── README.md
└── .gitignore
```

### Implementation rules

1. **Tuân thủ chính xác đặc tả 10 ràng buộc (C1-C10)** trong SPEC_Circuit_Paradigm2.md mục 4. Mỗi constraint phải tương ứng với một component được wire vào top-level.

2. **Dùng SMTVerifier của circomlib** (`circomlib/circuits/smt/smtverifier.circom`):
   - `fnc=0` cho inclusion proof (C4, C5)
   - `fnc=1` cho non-inclusion proof (C6)
   - Depth = 32 cho cả 3 trees

3. **Dùng EdDSAPoseidonVerifier** của circomlib cho C7. Message phải là `issuerState`. Pre-hash KHÔNG cần thiết vì EdDSAPoseidon đã hash internally — verify lại docs nếu nghi ngờ.

4. **Predicate (C8)** dùng `Mux4` để chọn giữa các operators dựa trên `predicateType`. Mỗi operator dùng `LessEqThan(252)` hoặc `GreaterEqThan(252)` từ `comparators.circom`. Nhớ rằng các comparator này yêu cầu inputs fit trong N bits → wire qua `Num2Bits` nếu cần.

5. **Pattern wiring:** Mỗi sub-circuit là một template riêng trong file của nó, top-level chỉ instantiate components và wire signals. KHÔNG inline logic phức tạp trong top-level.

6. **Public inputs declaration:** Chú ý cú pháp `component main {public [...]} = ...` ở Circom 2.x.

### Test requirements

Implement đầy đủ **9 test cases** ở mục 7 của SPEC. Mỗi test phải:

- Build một SMT thực sự bằng `@iden3/js-merkletree` hoặc tự build dùng circomlibjs
- Sign `issuerState` bằng EdDSA-Poseidon thực sự
- Generate witness, generate proof, verify proof
- Đối với negative cases: assert rằng witness generation FAIL với expected error message (không phải proof generation fail — vì lỗi sẽ phát hiện ở giai đoạn witness)

Format test:

```javascript
describe("CredentialAtomicQuery", () => {
  it("happy path: age >= 18", async () => { ... });
  it("rejects tampered attribute value", async () => {
    await expect(generateWitness(badInputs)).to.be.rejectedWith(/Constraint/);
  });
  // ... 7 cases khác
});
```

### Helper utilities cần build

**`helpers/smt.js`:**
```javascript
// API tối thiểu
async function buildClaimsTree(claims) -> { root, getProof(claim) }
async function buildRevocationTree(revokedNonces) -> { root, getNonInclusionProof(nonce) }
async function buildRootsTree(historicalRoots) -> { root, getProof(root) }
```

**`helpers/claim.js`:**
```javascript
function hashClaim({schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce}) -> Felt
function buildClaim(params) -> claimObject
```

**`helpers/eddsa.js`:**
```javascript
function signIssuerState(privateKey, state) -> {R8x, R8y, S}
function deriveIssuerId(pubKey) -> Felt
```

### Constraints về output

1. **Code phải compile thực sự được** với `circom 2.1.x --r1cs --wasm --sym`. Đừng viết pseudocode.

2. **Tests phải chạy được** với `npm test` (sau khi `npm install` và compile circuit). Document rõ các bước trong README.

3. **Comment dày đặc**: mỗi constraint group (C1-C10) phải có comment block giải thích tham chiếu về SPEC.

4. **Idiomatic Circom 2.x**: dùng `<==`, `===`, `signal input/output` đúng chuẩn. KHÔNG dùng cú pháp Circom 1.x cũ.

5. **README.md** phải có:
   - Mô tả ngắn (5-10 dòng)
   - Prerequisites (node, circom, snarkjs versions)
   - Step-by-step: install → compile → setup → test
   - Một sơ đồ ASCII đơn giản về luồng dữ liệu vào mạch
   - Link sang SPEC_Circuit_Paradigm2.md

### Quy trình làm việc đề xuất

Hãy làm theo thứ tự sau, KHÔNG nhảy bước:

1. Tạo `package.json`, cài deps, tạo cấu trúc thư mục.
2. Viết `lib/identity.circom`, `lib/claim.circom`, `lib/nullifier.circom`, `lib/predicate.circom` (4 files đơn giản trước).
3. Viết `credentialAtomicQuery.circom` (top-level, wiring).
4. Compile thử với `circom`. Sửa lỗi cú pháp nếu có.
5. Viết helpers (smt.js, claim.js, eddsa.js).
6. Viết test happy path. Chạy. Fix bugs.
7. Viết 8 test cases còn lại.
8. Viết README.md cuối cùng.

Sau MỖI bước, hãy chạy lệnh để verify output thực sự work, không chỉ "trông có vẻ đúng".

### Câu hỏi cần xác nhận trước khi bắt đầu

Nếu có bất kỳ điểm nào không rõ trong SPEC, hãy hỏi tôi TRƯỚC KHI bắt đầu code. Cụ thể, hãy confirm:

1. Có cần support `predicateType=3 (range)` ngay từ đầu không, hay chỉ cần `0,1,2`?
2. SMT depth 32 có phù hợp với scale dự kiến không (2^32 claims = 4 tỷ)?
3. Có cần thêm constraint nào về `currentTimestamp` (vd kiểm tra nó nằm trong khoảng hợp lý)?

Bắt đầu bằng việc summarize lại hiểu biết của bạn về task này (5-10 bullet points), rồi đặt các câu hỏi clarification ở trên, rồi mới code.

## PROMPT KẾT THÚC TẠI ĐÂY
