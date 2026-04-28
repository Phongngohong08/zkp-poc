pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// ============================================================
// C8 — Predicate Check (Kiểm tra điều kiện nghiệp vụ)
// ============================================================
//
// Mục đích:
//   Đây là nơi thực hiện "câu hỏi" của Verifier: "attributeValue có thoả mãn
//   điều kiện không?" mà KHÔNG tiết lộ attributeValue thực sự.
//   Mạch chỉ output tín hiệu valid=1 hoặc để constraint fail.
//
// Các loại predicate:
//   predicateType = 0 → equal:          attributeValue == predicateValue
//   predicateType = 1 → greater-or-equal: attributeValue >= predicateValue
//   predicateType = 2 → less-or-equal:   attributeValue <= predicateValue
//   predicateType = 3 → range:           predicateLow <= attributeValue <= predicateHigh
//
// Encoding cho range (type=3):
//   Vì mạch chỉ có một trường predicateValue, cả hai đầu [low, high] được nhét vào
//   bằng cách: predicateValue = low + high × 2^NBITS
//   Ví dụ NBITS=64, range [20, 30]: predicateValue = 20 + 30 × 2^64
//   Mạch giải mã bằng Num2Bits(128) → tách ra predicateLow và predicateHigh.
//
// Tại sao các so sánh dùng predicateLow thay vì predicateValue?
//   Khi type=3, predicateValue = low + high×2^64, giá trị này vượt quá 2^64.
//   LessEqThan(64) bên trong dùng Num2Bits(64) → sẽ fail với số > 2^64.
//   Giải pháp: luôn dùng predicateLow (64-bit thấp) cho mọi so sánh.
//   Với type 0/1/2, caller phải truyền predicateValue < 2^64, khi đó
//   predicateLow == predicateValue, kết quả không đổi.
//
// NBITS = 64: phù hợp cho tuổi, điểm số, năm sinh, v.v.
//   Num2Bits(64) là guard: nếu attributeValue >= 2^64, witness generation sẽ fail
//   ngay lập tức — ngăn các input không hợp lệ.
//
// Kỹ thuật selector (thay cho if/else):
//   Circom không có if/else theo nghĩa runtime — mọi nhánh đều được tính toán.
//   Ta dùng pattern: valid = isT0*equalOk + isT1*gteOk + isT2*lteOk + isT3*rangeOk
//   Đúng một trong bốn isT{i} bằng 1 (vì predicateType là public input), nên
//   tổng bằng đúng kết quả của nhánh tương ứng.

template PredicateCheck(NBITS) {
    // === Inputs ===
    signal input attributeValue; // Giá trị thuộc tính bí mật cần kiểm tra
    signal input predicateType;  // Loại so sánh: 0=eq, 1=gte, 2=lte, 3=range
    signal input predicateValue; // Ngưỡng so sánh (với range: low + high×2^NBITS)

    // === Output ===
    signal output valid;         // Phải bằng 1; nếu 0 → constraint "valid === 1" trong top-level fail

    // ---- Kiểm tra attributeValue nằm trong NBITS bits ----
    // Đây là bước bắt buộc: LessEqThan(NBITS) chỉ đúng với inputs < 2^NBITS.
    // Num2Bits sẽ throw nếu attributeValue >= 2^64 → chặn witness không hợp lệ.
    component bitsAttr = Num2Bits(NBITS);
    bitsAttr.in <== attributeValue;

    // ---- Giải mã predicateValue thành predicateLow và predicateHigh ----
    // Dùng Num2Bits(NBITS*2) để lấy 128 bits của predicateValue.
    // - Bits [0..NBITS-1]    → predicateLow  (giới hạn dưới cho range, hoặc ngưỡng đơn)
    // - Bits [NBITS..2*NBITS-1] → predicateHigh (giới hạn trên cho range)
    component bitsP = Num2Bits(NBITS * 2);
    bitsP.in <== predicateValue;

    signal predicateLow;   // 64 bits thấp của predicateValue
    signal predicateHigh;  // 64 bits cao của predicateValue (chỉ dùng khi type=3)
    var low_acc = 0;
    var high_acc = 0;
    for (var i = 0; i < NBITS; i++) {
        low_acc  += bitsP.out[i]        * (1 << i);
        high_acc += bitsP.out[NBITS + i] * (1 << i);
    }
    predicateLow  <== low_acc;
    predicateHigh <== high_acc;

    // ---- Nhánh 0: Equal (attributeValue == predicateLow) ----
    // Dùng predicateLow thay predicateValue để an toàn khi type=3 truyền số lớn.
    component isEqual = IsEqual();
    isEqual.in[0] <== attributeValue;
    isEqual.in[1] <== predicateLow;
    signal equalOk <== isEqual.out; // 1 nếu bằng nhau, 0 nếu khác

    // ---- Nhánh 1: Greater-or-equal (attributeValue >= predicateLow) ----
    // LessEqThan(n): out = 1 khi in[0] <= in[1]
    // Ta cần attributeValue >= predicateLow ↔ predicateLow <= attributeValue
    component lte1 = LessEqThan(NBITS);
    lte1.in[0] <== predicateLow;   // ngưỡng dưới
    lte1.in[1] <== attributeValue;
    signal gteOk <== lte1.out; // 1 nếu attributeValue >= predicateLow

    // ---- Nhánh 2: Less-or-equal (attributeValue <= predicateLow) ----
    component lte2 = LessEqThan(NBITS);
    lte2.in[0] <== attributeValue;
    lte2.in[1] <== predicateLow;   // ngưỡng trên
    signal lteOk <== lte2.out; // 1 nếu attributeValue <= predicateLow

    // ---- Nhánh 3: Range (predicateLow <= attributeValue <= predicateHigh) ----
    // Cần cả hai điều kiện cùng đúng → nhân hai kết quả (AND trong binary)
    component lteRangeL = LessEqThan(NBITS);
    lteRangeL.in[0] <== predicateLow;   // giới hạn dưới
    lteRangeL.in[1] <== attributeValue;

    component lteRangeH = LessEqThan(NBITS);
    lteRangeH.in[0] <== attributeValue;
    lteRangeH.in[1] <== predicateHigh;  // giới hạn trên

    // rangeOk = 1 chỉ khi CẢ HAI điều kiện đúng (1×1=1; 0×1=0; v.v.)
    signal rangeOk <== lteRangeL.out * lteRangeH.out;

    // ---- Selector: chọn kết quả theo predicateType ----
    // isT{i}.out = 1 nếu predicateType == i, ngược lại = 0.
    // Vì predicateType là public input, đúng một isT{i} bằng 1 tại runtime.
    component isT0 = IsEqual();
    isT0.in[0] <== predicateType;
    isT0.in[1] <== 0;

    component isT1 = IsEqual();
    isT1.in[0] <== predicateType;
    isT1.in[1] <== 1;

    component isT2 = IsEqual();
    isT2.in[0] <== predicateType;
    isT2.in[1] <== 2;

    component isT3 = IsEqual();
    isT3.in[0] <== predicateType;
    isT3.in[1] <== 3;

    // Tính tổng có trọng số: chỉ đúng một sel{i} ≠ 0
    // valid = 1 nếu nhánh được chọn cho kết quả đúng, = 0 nếu điều kiện không thoả
    signal sel0 <== isT0.out * equalOk;
    signal sel1 <== isT1.out * gteOk;
    signal sel2 <== isT2.out * lteOk;
    signal sel3 <== isT3.out * rangeOk;

    valid <== sel0 + sel1 + sel2 + sel3;
    // Top-level circuit sẽ ép buộc: valid === 1
}
