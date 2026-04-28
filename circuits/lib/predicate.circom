pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// C8 — Predicate / Business Logic
// predicateType:
//   0 = equal             (attributeValue == predicateValue)
//   1 = greater-or-equal  (attributeValue >= predicateValue)
//   2 = less-or-equal     (attributeValue <= predicateValue)
//   3 = range             (predicateLow <= attributeValue <= predicateHigh)
//       predicateValue encodes both bounds: predicateValue = low + high * 2^128
//
// NBITS = 64 keeps the value domain reasonable for age/score/etc attributes.
// All inputs are assumed to fit within NBITS; the Num2Bits decomposition
// enforces this and rejects out-of-range witnesses.

template PredicateCheck(NBITS) {
    signal input attributeValue;
    signal input predicateType;   // 0,1,2,3
    signal input predicateValue;  // for range: low = predicateValue & ((1<<NBITS)-1), high = predicateValue >> NBITS

    signal output valid;          // must be 1

    // ---- Bit-range enforcement ----
    component bitsAttr = Num2Bits(NBITS);
    bitsAttr.in <== attributeValue;

    // ---- Decode low / high for range predicate ----
    // We use a single predicateValue field. For range (type=3):
    //   predicateValue = predicateLow + predicateHigh * 2^NBITS
    // Extract low NBITS as predicateLow, upper NBITS as predicateHigh.
    component bitsP = Num2Bits(NBITS * 2);
    bitsP.in <== predicateValue;

    // Reconstruct low and high from bits
    signal predicateLow;
    signal predicateHigh;
    var low_acc = 0;
    var high_acc = 0;
    for (var i = 0; i < NBITS; i++) {
        low_acc  += bitsP.out[i] * (1 << i);
        high_acc += bitsP.out[NBITS + i] * (1 << i);
    }
    predicateLow  <== low_acc;
    predicateHigh <== high_acc;

    // ---- Equal (type 0) ----
    // Use predicateLow so that the range encoding (type=3) doesn't overflow NBITS here.
    // For types 0,1,2 the caller must pass predicateValue < 2^NBITS (high bits == 0),
    // so predicateLow == predicateValue in those cases.
    component isEqual = IsEqual();
    isEqual.in[0] <== attributeValue;
    isEqual.in[1] <== predicateLow;
    signal equalOk <== isEqual.out;

    // ---- Greater-or-equal (type 1): attributeValue >= predicateLow ----
    // LessEqThan(n).out = 1 iff in[0] <= in[1]
    component lte1 = LessEqThan(NBITS);
    lte1.in[0] <== predicateLow;
    lte1.in[1] <== attributeValue;
    signal gteOk <== lte1.out;

    // ---- Less-or-equal (type 2): attributeValue <= predicateLow ----
    component lte2 = LessEqThan(NBITS);
    lte2.in[0] <== attributeValue;
    lte2.in[1] <== predicateLow;
    signal lteOk <== lte2.out;

    // ---- Range (type 3): predicateLow <= attributeValue <= predicateHigh ----
    component lteRangeL = LessEqThan(NBITS);
    lteRangeL.in[0] <== predicateLow;
    lteRangeL.in[1] <== attributeValue;

    component lteRangeH = LessEqThan(NBITS);
    lteRangeH.in[0] <== attributeValue;
    lteRangeH.in[1] <== predicateHigh;

    signal rangeOk <== lteRangeL.out * lteRangeH.out;

    // ---- Select result based on predicateType ----
    // predicateType is a public input treated as a constant at witness time.
    // We build a selector: result = (type==0)*eq + (type==1)*gte + (type==2)*lte + (type==3)*range
    // Encode type as 2-bit number and use Mux4 pattern manually.

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

    // Exactly one selector is active (public input guarantees it).
    // selected = isT0*equalOk + isT1*gteOk + isT2*lteOk + isT3*rangeOk
    signal sel0 <== isT0.out * equalOk;
    signal sel1 <== isT1.out * gteOk;
    signal sel2 <== isT2.out * lteOk;
    signal sel3 <== isT3.out * rangeOk;

    valid <== sel0 + sel1 + sel2 + sel3;
}
