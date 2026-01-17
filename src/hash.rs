//! Keccak256 hashing using Soroban SDK directly.

use soroban_sdk::{Bytes, BytesN, Env};

/// Compute keccak256 hash using Soroban's host function.
#[inline(always)]
pub fn hash32(env: &Env, data: &[u8]) -> [u8; 32] {
    let input = Bytes::from_slice(env, data);
    let digest: BytesN<32> = env.crypto().keccak256(&input).into();
    digest.into()
}
