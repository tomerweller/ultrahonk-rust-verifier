//! BN254 elliptic curve operations for the verifier.
//! Directly uses Soroban SDK crypto functions.

use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr as HostFr},
    BytesN, Env, Vec as SorobanVec,
};

use crate::{error::VerifierError, field::Fr, types::G1Point};
use crate::types::G2_POINT_SIZE;

/// BN254 base field modulus (Fq) in big-endian
/// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
const FQ_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// RHS G2 point for pairing check (big-endian: x.c1 || x.c0 || y.c1 || y.c0)
/// This is the second generator point used in the KZG setup.
pub const RHS_G2_BYTES: [u8; G2_POINT_SIZE] = [
    // x.c1
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    // x.c0
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    // y.c1
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
    // y.c0
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
];

/// LHS G2 point for pairing check (big-endian: x.c1 || x.c0 || y.c1 || y.c0)
/// This is the G2 generator point (negative of the standard generator for pairing equation).
pub const LHS_G2_BYTES: [u8; G2_POINT_SIZE] = [
    // x.c1
    0x26, 0x0e, 0x01, 0xb2, 0x51, 0xf6, 0xf1, 0xc7, 0xe7, 0xff, 0x4e, 0x58, 0x07, 0x91, 0xde, 0xe8,
    0xea, 0x51, 0xd8, 0x7a, 0x35, 0x8e, 0x03, 0x8b, 0x4e, 0xfe, 0x30, 0xfa, 0xc0, 0x93, 0x83, 0xc1,
    // x.c0
    0x01, 0x18, 0xc4, 0xd5, 0xb8, 0x37, 0xbc, 0xc2, 0xbc, 0x89, 0xb5, 0xb3, 0x98, 0xb5, 0x97, 0x4e,
    0x9f, 0x59, 0x44, 0x07, 0x3b, 0x32, 0x07, 0x8b, 0x7e, 0x23, 0x1f, 0xec, 0x93, 0x88, 0x83, 0xb0,
    // y.c1
    0x04, 0xfc, 0x63, 0x69, 0xf7, 0x11, 0x0f, 0xe3, 0xd2, 0x51, 0x56, 0xc1, 0xbb, 0x9a, 0x72, 0x85,
    0x9c, 0xf2, 0xa0, 0x46, 0x41, 0xf9, 0x9b, 0xa4, 0xee, 0x41, 0x3c, 0x80, 0xda, 0x6a, 0x5f, 0xe4,
    // y.c0
    0x22, 0xfe, 0xbd, 0xa3, 0xc0, 0xc0, 0x63, 0x2a, 0x56, 0x47, 0x5b, 0x42, 0x14, 0xe5, 0x61, 0x5e,
    0x11, 0xe6, 0xdd, 0x3f, 0x96, 0xe6, 0xce, 0xa2, 0x85, 0x4a, 0x87, 0xd4, 0xda, 0xcc, 0x5e, 0x55,
];

/// Multi-scalar multiplication on G1: sum of s_i * C_i
/// Uses Soroban's g1_mul and g1_add host functions directly.
#[inline(always)]
pub fn g1_msm(env: &Env, coms: &[G1Point], scalars: &[Fr]) -> Result<G1Point, VerifierError> {
    if coms.len() != scalars.len() {
        return Err(VerifierError::MsmLengthMismatch);
    }

    let bn = env.crypto().bn254();

    // Soroban does not expose MSM, so use g1_mul plus g1_add in a loop.
    let mut acc: Option<Bn254G1Affine> = None;
    for (pt, scalar) in coms.iter().zip(scalars.iter()) {
        // Convert G1Point bytes directly to Soroban type
        let host_pt = Bn254G1Affine::from_bytes(BytesN::from_array(env, &pt.bytes));
        let host_scalar = HostFr::from_bytes(BytesN::from_array(env, &scalar.to_bytes()));
        let term = bn.g1_mul(&host_pt, &host_scalar);
        acc = Some(match acc {
            Some(current) => bn.g1_add(&current, &term),
            None => term,
        });
    }

    match acc {
        Some(result) => {
            // Convert result back to G1Point bytes
            let mut bytes = [0u8; 64];
            result.to_bytes().copy_into_slice(&mut bytes);
            Ok(G1Point::from_bytes(bytes))
        }
        None => Ok(G1Point::zero()),
    }
}

/// Pairing product check e(P0, rhs_g2) * e(P1, lhs_g2) == 1
/// Uses Soroban's pairing_check host function directly.
#[inline(always)]
pub fn pairing_check(env: &Env, p0: &G1Point, p1: &G1Point) -> bool {
    // Convert G1 points directly from bytes
    let g1_p0 = Bn254G1Affine::from_bytes(BytesN::from_array(env, &p0.bytes));
    let g1_p1 = Bn254G1Affine::from_bytes(BytesN::from_array(env, &p1.bytes));

    // Use hardcoded G2 point bytes
    let g2_rhs = Bn254G2Affine::from_bytes(BytesN::from_array(env, &RHS_G2_BYTES));
    let g2_lhs = Bn254G2Affine::from_bytes(BytesN::from_array(env, &LHS_G2_BYTES));

    let mut g1_points = SorobanVec::new(env);
    g1_points.push_back(g1_p0);
    g1_points.push_back(g1_p1);

    let mut g2_points = SorobanVec::new(env);
    g2_points.push_back(g2_rhs);
    g2_points.push_back(g2_lhs);

    env.crypto().bn254().pairing_check(g1_points, g2_points)
}

/// Negate a G1 point by computing -y mod p (the BN254 base field modulus).
/// For the zero point (all zeros), returns the zero point unchanged.
/// This is pure math - no Soroban calls needed.
#[inline(always)]
pub fn negate(pt: &G1Point) -> G1Point {
    let mut result = pt.bytes;

    // Extract y coordinate (bytes 32-63)
    let y = &pt.bytes[32..64];

    // Check if y is zero (point at infinity)
    let mut is_zero = true;
    for &b in y {
        if b != 0 {
            is_zero = false;
            break;
        }
    }

    if is_zero {
        return G1Point { bytes: result };
    }

    // Compute p - y using big-endian subtraction
    let neg_y = sub_mod(&FQ_MODULUS, y);
    result[32..64].copy_from_slice(&neg_y);

    G1Point { bytes: result }
}

/// Subtract b from a (both 32-byte big-endian), assuming a >= b.
/// Returns a - b as 32-byte big-endian.
#[inline(always)]
fn sub_mod(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;

    // Process from least significant byte (index 31) to most significant (index 0)
    for i in (0..32).rev() {
        let ai = a[i] as u16;
        let bi = b[i] as u16;
        let diff = ai.wrapping_sub(bi).wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if ai < bi + borrow { 1 } else { 0 };
    }

    result
}

/// Helper functions for EC operations
pub mod helpers {
    use super::*;

    /// Negate a G1 point (compute -P by negating Y coordinate)
    #[inline(always)]
    pub fn negate(pt: &G1Point) -> G1Point {
        super::negate(pt)
    }
}
