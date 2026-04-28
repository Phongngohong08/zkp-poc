# ZKP Credential Atomic Query — Paradigm 2

Mạch ZKP cho phép Holder chứng minh một thuộc tính trong credential của mình thoả mãn một điều kiện (ví dụ: tuổi ≥ 18) **mà không tiết lộ** danh tính, giá trị thuộc tính, hay bất kỳ thông tin nào khác.

Stack: **Circom 2.x · SnarkJS · BN254 · Groth16 · Iden3 SMT**

---

## Prerequisites

| Công cụ | Phiên bản | Cài đặt |
|---------|-----------|---------|
| Node.js | ≥ 18 | [nodejs.org](https://nodejs.org) |
| circom  | 2.1.x | `cargo install circom` hoặc tải binary từ [releases](https://github.com/iden3/circom/releases) |
| snarkjs | tự động qua npm | — |

Kiểm tra circom nằm trong PATH:
```bash
circom --version   # circom compiler 2.1.x
```

---

## Cài đặt và chạy

```bash
# 1. Cài dependencies
npm install

# 2. Compile circuit → tạo .r1cs, .wasm, .sym trong build/
npm run compile

# 3. Trusted setup (phase 2) → tạo .zkey và verification_key.json
#    Lần đầu sẽ tải file Powers of Tau ~38 MB
npm run setup

# 4. Chạy toàn bộ 9 test cases
npm test

# Chạy một test cụ thể
npx mocha test/credentialAtomicQuery.test.js --timeout 120000 --grep "TC1"
```

> **Lưu ý quan trọng:** Mỗi khi sửa bất kỳ file `.circom` nào, phải chạy lại **cả hai** `npm run compile` và `npm run setup`. Nếu chỉ compile mà không setup lại, zkey sẽ không khớp với r1cs mới — proof sẽ được tạo ra nhưng verify luôn trả về `false`.

---

## Kiến trúc dữ liệu

```
                        ┌───────────────��─────────┐
                        │       IssuerState        │
                        │  Poseidon(Cl_R, Re_R, Ro_R)│
                        │  (được Issuer ký EdDSA)  │
                        └────────────┬────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                       ▼
        claimsTree             revocationTree           rootsTree
     (Cl_R = root)            (Re_R = root)          (Ro_R = root)
    ┌─────────────┐          ┌─────────────┐        ┌─────────────┐
    │ leafHash_1  │          │  revNonce_A │        │   Cl_R_old  │
    │ leafHash_2  │          │  revNonce_B │        │   Cl_R_cur  │
    │    ...      │          │    ...      │        │    ...      │
    └─────────────┘          └─────────────┘        └─────────────┘
    Chứa claims             Chứa nonces của         Lịch sử các
    đã phát hành            claims đã bị revoke     claimsTree roots

leafHash  = Poseidon(schemaHash, subjectId, attributeKey, attributeValue, expiry, revNonce)
idcom     = Poseidon(skid, nullifierSeed)   ← subjectId trong claim
issuerId  = Poseidon(pubKeyAx, pubKeyAy)
nullifier = Poseidon(nullifierSeed, contextId)
```

---

## Luồng chạy test (`npm test`)

Test suite gồm 9 cases, tất cả dùng chung hàm `buildInputs()` tạo một bộ witness hợp lệ hoàn chỉnh, sau đó mỗi negative test ghi đè đúng một trường để vi phạm một constraint.

```
npm test
   │
   ▼
mocha khởi động
   │
   ├─ before(): khởi tạo Poseidon instance (circomlibjs)
   │
   ├─ TC1 happy path ──────────────────────────────────────────┐
   │    │                                                       │
   │    ├─ buildInputs()                                        │
   │    │    ├─ Tính idcom = Poseidon(skid, nullifierSeed)      │
   │    │    ├─ hashClaim() → leafHash                          │
   │    │    ├─ buildClaimsTree([leafHash]) → claimsRoot        │
   │    │    ├─ buildRevocationTree([]) → revRoot (cây rỗng)    │
   │    │    ├─ buildRootsTree([claimsRoot]) → rootsRoot        │
   │    │    ├─ issuerState = Poseidon(3 roots)                 │
   │    │    └─ signIssuerState(privKey, issuerState)           │
   │    │                                                       │
   │    └─ generateAndVerify(inputs)                            │
   │         ├─ snarkjs.groth16.fullProve()                     │
   │         │    ├─ WASM tính witness (kiểm tra C1-C10)        │
   │         │    └─ Groth16 prover tạo proof (π_A, π_B, π_C) │
   │         ├─ snarkjs.zKey.exportVerificationKey()            │
   │         └─ snarkjs.groth16.verify() → true ✓              │
   │                                                            │
   ├─ TC2-TC7: negative tests ─────────────────────────────────┘
   │    │
   │    ├─ buildInputs({ claimAttributeValue: 17n })  ← override 1 trường
   │    └─ generateWitness() → WASM throw constraint error ✓
   │         (witness fail ngay trong WASM, trước khi tạo proof)
   │
   ├─ TC8 unlinkability: 2 contextId → 2 nullifier khác nhau ✓
   │
   └─ TC9 range predicate: predicateValue = 20 + 30×2^64 → valid ✓
```

### Các constraint và test tương ứng

| Test | Constraint bị vi phạm | Lý do fail |
|------|----------------------|------------|
| TC1  | — (happy path)       | Proof hợp lệ, verify = true |
| TC2  | C3 + C4 (Merkle)     | attributeValue thay đổi → leafHash khác → inclusion proof sai |
| TC3  | C7 (EdDSA)           | Public key giả → chữ ký không verify được |
| TC4  | C1 (identity)        | skid sai → idcom ≠ subjectId |
| TC5  | C9 (expiry)          | currentTimestamp > claimExpiry |
| TC6  | C6 + C7 (non-revocation) | revNonce có trong revTree → non-inclusion proof sai |
| TC7  | C2 (schema match)    | schemaHash claim ≠ requestedSchemaHash |
| TC8  | — (unlinkability)    | Hai proof tạo được, nullifier1 ≠ nullifier2 |
| TC9  | — (range predicate)  | age=25 ∈ [20,30] → valid |

---

## Luồng `npm run prove` (tạo proof từ file JSON)

`prove.sh` tách quá trình thành 3 bước riêng biệt — hữu ích để hiểu từng giai đoạn, debug, hoặc tích hợp vào pipeline bên ngoài.

```
npm run prove [-- path/to/input.json]
   │
   │  Mặc định: test/fixtures/happyPath.json
   │
   ├─ BƯỚC 1: Tính witness
   │    node build/credentialAtomicQuery_js/generate_witness.js \
   │         credentialAtomicQuery.wasm  \
   │         input.json                  \
   │         build/witness.wtns
   │
   │    - WASM đọc input.json (tất cả public + private inputs)
   │    - Thực thi mạch, tính giá trị tất cả signals
   │    - Kiểm tra mọi constraint (C1-C10): nếu fail → dừng ngay với error
   │    - Output: witness.wtns (binary, ~vài MB)
   │
   ├─ BƯỚC 2: Tạo proof Groth16
   │    snarkjs groth16 prove \
   │         build/credentialAtomicQuery_final.zkey \
   │         build/witness.wtns                     \
   │         build/proof.json                       \
   │         build/public.json
   │
   │    - Prover đọc zkey (proving key ~13 MB) + witness.wtns
   │    - Tính 3 điểm elliptic (π_A, π_B, π_C) trên đường cong BN254
   │    - Output:
   │        proof.json   → chứa π_A, π_B, π_C (256 bytes khi serialize)
   │        public.json  → chứa public inputs + nullifierHash output
   │
   └─ BƯỚC 3: Verify proof
        snarkjs groth16 verify \
             build/verification_key.json \
             build/public.json           \
             build/proof.json
   
        - Verifier đọc vkey (nhỏ, ~4 KB) + proof + public signals
        - Thực hiện 3 phép pairing trên BN254
        - In "OK!" nếu hợp lệ, lỗi nếu không
        - Verifier CHỈ cần vkey + proof + public.json (không cần private inputs)
```

### Tạo file input.json để dùng với prove.sh

`scripts/generate_fixture.js` là script chính thức để tạo `test/fixtures/happyPath.json` — dùng logic giống hệt `buildInputs()` trong test suite:

```bash
node scripts/generate_fixture.js
# → Ghi test/fixtures/happyPath.json
```

Script sẽ: khởi tạo Poseidon → xây 3 cây SMT → ký EdDSA → ghi JSON với tất cả BigInt đã convert sang string (snarkjs tự xử lý khi đọc lại).

Sau khi có file fixture, chạy proof như bình thường:

```bash
npm run prove                          # dùng test/fixtures/happyPath.json (mặc định)
npm run prove -- path/to/custom.json   # dùng file khác
```

> **Khi nào cần chạy lại generate_fixture.js?** Mỗi khi thay đổi tham số claim (schemaHash, attributeValue, revNonce, …), thay private key, hoặc muốn tạo fixture với predicate/contextId khác.

---

## Sơ đồ luồng dữ liệu qua mạch

```
PRIVATE INPUTS                    PUBLIC INPUTS
─────────────                     ─────────────
skid ──────────────┐              issuerId ─────────────────────────────┐
nullifierSeed ─────┤              issuerState ───────────────────────┐  │
                   ▼                                                  │  │
              [C1: Identity]                                          │  │
              idcom = P(skid,seed)◄── claimSubjectId ─────────────┐ │  │
                                                                   │ │  │
claimSchemaHash ───────────────────────── requestedSchemaHash ─[C2]│ │  │
claimAttributeKey ─────────────────────── requestedAttributeKey ─[C2] │  │
                                                                       │  │
claimSchemaHash ─┐                                                     │  │
claimSubjectId ──┤                                                     │  │
claimAttributeKey┤                                                     │  │
claimAttributeValue─[C3: leafHash]                                     │  │
claimExpiry ─────┤      │                                              │  │
claimRevNonce ───┘      │                                              │  │
                        ▼                                              │  │
claimMtp ──────────[C4: SMT inclusion] claimsTreeRoot ─────────────┐  │  │
                                              │                     │  │  │
rootsMtp ──────────[C5: SMT inclusion] rootsTreeRoot ──────────┐   │  │  │
                                                                │   │  │  │
revMtp ────────────[C6: SMT NON-inclusion] revocationTreeRoot ─┤   │  │  │
revMtpOldKey ──────┘                                            │   │  │  │
revMtpOldValue                                                  │   │  │  │
revMtpIsOld0                                                    │   │  │  │
                                                                ▼   ▼  │  │
issuerSigR8x ──┐                                          [C7: P(Cl,Re,Ro)=issuerState]
issuerSigR8y ──┤──[C7: EdDSA verify]                           └──────►┘  │
issuerSigS ────┘         ▲                                                 │
issuerPubKeyAx ──────────┤──[C7: P(Ax,Ay) = issuerId]────────────────────►┘
issuerPubKeyAy ──────────┘

claimAttributeValue ──────────────[C8: Predicate]◄── predicateType  (public)
                                        ▲         ◄── predicateValue (public)
                                        │
currentTimestamp ─────────────────[C9: Expiry]◄── claimExpiry

nullifierSeed ────────────────────[C10: Nullifier]◄── contextId (public)
                                        │
                                        ▼
                                  nullifierHash ──► PUBLIC OUTPUT
```

---

## Cấu trúc thư mục

```
zkp-poc/
├── circuits/
│   ├── credentialAtomicQuery.circom   # Top-level: wiring C1-C10
│   └── lib/
│       ├── identity.circom            # C1: idcom = Poseidon(skid, seed)
│       ├── claim.circom               # C3: leafHash = Poseidon(6 fields)
│       ├── predicate.circom           # C8: eq / gte / lte / range
│       └── nullifier.circom           # C10: nullifier = Poseidon(seed, ctx)
├── test/
│   ├── credentialAtomicQuery.test.js  # 9 test cases
│   ├── fixtures/
│   │   └── happyPath.json             # Canonical happy-path input cho prove.sh
│   └── helpers/
│       ├── smt.js                     # Build SMT, generate proofs
│       ├── claim.js                   # Build + hash claim
│       └── eddsa.js                   # Sign issuerState, derive issuerId
├── scripts/
│   ├── compile.sh                     # circom → r1cs + wasm
│   ├── setup.sh                       # phase 2 trusted setup → zkey
│   ├── prove.sh                       # witness → proof → verify
│   └── generate_fixture.js            # Tạo test/fixtures/happyPath.json
├── build/                             # Generated (gitignored)
├── Spec_va_Prompt_Paradigm2.md        # Đặc tả kỹ thuật đầy đủ
└── CLAUDE.md                          # Hướng dẫn cho Claude Code
```

---

## Ước tính hiệu năng

| Thành phần | Constraints |
|-----------|------------|
| 3× SMTVerifier depth 20 | ~18.000 |
| EdDSA-Poseidon verify | ~4.000 |
| Poseidon hashing | ~1.500 |
| Comparators + Num2Bits | ~800 |
| **Tổng** | **~24.300** |

| Môi trường | Proving time (ước tính) |
|-----------|------------------------|
| Laptop (M1/M2) | ~2–4 giây |
| Laptop (x86 mid-range) | ~5–10 giây |
| Mobile | ~20–40 giây |

Proof size: **256 bytes** (Groth16 cố định).
Gas verify on-chain (Solidity verifier): **~250k gas**.
