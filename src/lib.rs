#![cfg_attr(not(feature = "std"), no_std)]

// Note: arkworks internally requires alloc even in no_std mode.
// The alloc crate is provided by the soroban-sdk when compiling for Soroban.
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod debug;
pub mod ec;
pub mod error;
pub mod field;
pub mod hash;
pub mod relations;
pub mod shplemini;
pub mod sumcheck;
pub mod transcript;
pub mod types;
pub mod utils;
pub mod verifier;
pub const PROOF_FIELDS: usize = 456;
pub const PROOF_BYTES: usize = PROOF_FIELDS * 32;

pub use error::VerifierError;
pub use verifier::UltraHonkVerifier;
