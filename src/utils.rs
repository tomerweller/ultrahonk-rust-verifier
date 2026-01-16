//! Utilities for loading Proof and VerificationKey (no arkworks EC types, no BigUint).

use crate::field::Fr;
use crate::types::{
    G1Point, Proof, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH, CONST_PROOF_SIZE_LOG_N,
    G1_POINT_SIZE, NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
};
use crate::PROOF_BYTES;
use core::array;

/// Convert a 32-byte big-endian array into an Fr.
#[inline(always)]
fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(bytes)
}

/// Split a 32-byte BE field element into (lo136, hi118) each as 32-byte BE.
/// This is used for transcript hashing to match the Barretenberg split-limb format.
pub fn bytes32_to_halves_be(bytes: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // 136 bits = 17 bytes, 118 bits = 15 bytes (rounded up)
    // In BE 32-byte array:
    // - lo136 is bits 0-135, which occupy bytes 15-31 (17 bytes)
    // - hi118 is bits 136-253, which occupy bytes 0-14 (15 bytes) after masking

    let mut lo = [0u8; 32];
    let mut hi = [0u8; 32];

    // lo136: copy bytes 15-31 (the lower 17 bytes = 136 bits)
    lo[15..32].copy_from_slice(&bytes[15..32]);

    // hi118: copy bytes 0-14 (the upper 15 bytes, but we need to shift right by the bit offset)
    // Since 136 = 17*8 exactly, there's no bit offset - we just take bytes 0-14
    // But we need to right-align them in the output (put in bytes 17-31)
    hi[17..32].copy_from_slice(&bytes[0..15]);

    (lo, hi)
}

/// Recombine split-limb format back to a 32-byte BE field element.
/// Input: 64 bytes as [lo_be(32)] [hi_be(32)] where:
/// - lo is the lower 136 bits (right-aligned in 32 bytes)
/// - hi is the upper 118 bits (right-aligned in 32 bytes)
/// Output: full 254-bit value as 32-byte BE = lo + (hi << 136)
#[inline(always)]
fn recombine_split_limbs(lo: &[u8], hi: &[u8]) -> [u8; 32] {
    debug_assert!(lo.len() == 32 && hi.len() == 32);
    let mut result = [0u8; 32];

    // lo136 occupies bits 0-135 → result bytes 15-31 (17 bytes)
    // lo is right-aligned in 32 bytes, so meaningful data is in lo[15..32]
    result[15..32].copy_from_slice(&lo[15..32]);

    // hi118 << 136 occupies bits 136-253 → result bytes 0-14 (15 bytes)
    // hi is right-aligned in 32 bytes, so meaningful data is in hi[17..32]
    result[0..15].copy_from_slice(&hi[17..32]);

    result
}

/// Parse a G1 point from proof format (split-limb encoding: 128 bytes total).
/// Format: [x_lo(32), x_hi(32), y_lo(32), y_hi(32)]
#[inline(always)]
fn bytes_to_g1_proof_point(bytes: &[u8], cur: &mut usize) -> G1Point {
    let x_lo = &bytes[*cur..*cur + 32];
    let x_hi = &bytes[*cur + 32..*cur + 64];
    let y_lo = &bytes[*cur + 64..*cur + 96];
    let y_hi = &bytes[*cur + 96..*cur + 128];
    *cur += 128;

    let x_bytes = recombine_split_limbs(x_lo, x_hi);
    let y_bytes = recombine_split_limbs(y_lo, y_hi);

    let mut point_bytes = [0u8; G1_POINT_SIZE];
    point_bytes[..32].copy_from_slice(&x_bytes);
    point_bytes[32..].copy_from_slice(&y_bytes);

    G1Point::from_bytes(point_bytes)
}

/// Parse a G1 point from VK format (direct encoding: 64 bytes, x || y).
#[inline(always)]
fn read_vk_point(bytes: &[u8], idx: &mut usize) -> G1Point {
    let mut point_bytes = [0u8; G1_POINT_SIZE];
    point_bytes.copy_from_slice(&bytes[*idx..*idx + 64]);
    *idx += 64;
    // No validation - Soroban host will validate when used in EC operations
    G1Point::from_bytes(point_bytes)
}

/// Helper: read next 32 bytes as Fr
#[inline(always)]
fn bytes_to_fr(bytes: &[u8], cur: &mut usize) -> Fr {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[*cur..*cur + 32]);
    *cur += 32;
    bytes32_to_fr(&arr)
}

/// Load a Proof from a byte array.
///
/// Note (bb v0.87.0): G1 coordinates are encoded as two limbs per coordinate
/// using the (lo136, hi<=118) split and stored in the order (x_lo, x_hi, y_lo, y_hi).
pub fn load_proof(proof_bytes: &[u8]) -> Proof {
    assert_eq!(proof_bytes.len(), PROOF_BYTES, "proof bytes len");
    let mut boundary = 0usize;

    // 0) pairing point object
    let pairing_point_object: [Fr; PAIRING_POINTS_SIZE] =
        array::from_fn(|_| bytes_to_fr(proof_bytes, &mut boundary));

    // 1) w1, w2, w3
    let w1 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let w2 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let w3 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 2) lookup_read_counts, lookup_read_tags
    let lookup_read_counts = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let lookup_read_tags = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 3) w4
    let w4 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 4) lookup_inverses, z_perm
    let lookup_inverses = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let z_perm = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 5) sumcheck_univariates
    let mut sumcheck_univariates =
        [[Fr::zero(); BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];
    for r in 0..CONST_PROOF_SIZE_LOG_N {
        for i in 0..BATCHED_RELATION_PARTIAL_LENGTH {
            sumcheck_univariates[r][i] = bytes_to_fr(proof_bytes, &mut boundary);
        }
    }

    // 6) sumcheck_evaluations
    let sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES] =
        array::from_fn(|_| bytes_to_fr(proof_bytes, &mut boundary));

    // 7) gemini_fold_comms
    let gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1] =
        array::from_fn(|_| bytes_to_g1_proof_point(proof_bytes, &mut boundary));

    // 8) gemini_a_evaluations
    let gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N] =
        array::from_fn(|_| bytes_to_fr(proof_bytes, &mut boundary));

    // 9) shplonk_q, kzg_quotient
    let shplonk_q = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let kzg_quotient = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    Proof {
        pairing_point_object,
        w1,
        w2,
        w3,
        w4,
        lookup_read_counts,
        lookup_read_tags,
        lookup_inverses,
        z_perm,
        sumcheck_univariates,
        sumcheck_evaluations,
        gemini_fold_comms,
        gemini_a_evaluations,
        shplonk_q,
        kzg_quotient,
    }
}

/// Load a VerificationKey from bytes.
/// No validation is performed - Soroban host will validate points when used.
pub fn load_vk_from_bytes(bytes: &[u8]) -> Option<VerificationKey> {
    const HEADER_WORDS: usize = 4;
    const NUM_POINTS: usize = 27;
    const EXPECTED_LEN: usize = HEADER_WORDS * 8 + NUM_POINTS * 64;
    if bytes.len() != EXPECTED_LEN {
        return None;
    }

    fn read_u64(bytes: &[u8], idx: &mut usize) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[*idx..*idx + 8]);
        *idx += 8;
        u64::from_be_bytes(arr)
    }

    let mut idx = 0usize;
    let circuit_size = read_u64(bytes, &mut idx);
    let log_circuit_size = read_u64(bytes, &mut idx);
    let public_inputs_size = read_u64(bytes, &mut idx);
    let _pub_inputs_offset = read_u64(bytes, &mut idx);

    let qm = read_vk_point(bytes, &mut idx);
    let qc = read_vk_point(bytes, &mut idx);
    let ql = read_vk_point(bytes, &mut idx);
    let qr = read_vk_point(bytes, &mut idx);
    let qo = read_vk_point(bytes, &mut idx);
    let q4 = read_vk_point(bytes, &mut idx);
    let q_lookup = read_vk_point(bytes, &mut idx);
    let q_arith = read_vk_point(bytes, &mut idx);
    let q_delta_range = read_vk_point(bytes, &mut idx);
    let q_elliptic = read_vk_point(bytes, &mut idx);
    let q_aux = read_vk_point(bytes, &mut idx);
    let q_poseidon2_external = read_vk_point(bytes, &mut idx);
    let q_poseidon2_internal = read_vk_point(bytes, &mut idx);
    let s1 = read_vk_point(bytes, &mut idx);
    let s2 = read_vk_point(bytes, &mut idx);
    let s3 = read_vk_point(bytes, &mut idx);
    let s4 = read_vk_point(bytes, &mut idx);
    let id1 = read_vk_point(bytes, &mut idx);
    let id2 = read_vk_point(bytes, &mut idx);
    let id3 = read_vk_point(bytes, &mut idx);
    let id4 = read_vk_point(bytes, &mut idx);
    let t1 = read_vk_point(bytes, &mut idx);
    let t2 = read_vk_point(bytes, &mut idx);
    let t3 = read_vk_point(bytes, &mut idx);
    let t4 = read_vk_point(bytes, &mut idx);
    let lagrange_first = read_vk_point(bytes, &mut idx);
    let lagrange_last = read_vk_point(bytes, &mut idx);

    Some(VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        qm,
        qc,
        ql,
        qr,
        qo,
        q4,
        q_lookup,
        q_arith,
        q_delta_range,
        q_elliptic,
        q_aux,
        q_poseidon2_external,
        q_poseidon2_internal,
        s1,
        s2,
        s3,
        s4,
        id1,
        id2,
        id3,
        id4,
        t1,
        t2,
        t3,
        t4,
        lagrange_first,
        lagrange_last,
    })
}
