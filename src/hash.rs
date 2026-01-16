// In std builds we always keep a pure-Rust Keccak backend for tests and tools.
// For no_std + soroban-precompile (Soroban WASM) we rely solely on the host backend.
#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
use sha3::{Digest, Keccak256};

/// Transcript hash backend abstraction trait.
pub trait HashOps: Send + Sync {
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
pub struct KeccakBackend;

#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
impl HashOps for KeccakBackend {
    #[inline(always)]
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
static KECCAK_BACKEND: KeccakBackend = KeccakBackend;

// ============================================================================
// Soroban static backend (no allocator, no Box)
// ============================================================================

#[cfg(all(feature = "soroban-precompile", not(feature = "std"), not(test)))]
mod soroban_hash_backend {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, Ordering};

    struct SorobanHashBackend {
        initialized: AtomicBool,
        hash_fn: UnsafeCell<Option<fn(&[u8]) -> [u8; 32]>>,
    }

    unsafe impl Sync for SorobanHashBackend {}

    static SOROBAN_HASH: SorobanHashBackend = SorobanHashBackend {
        initialized: AtomicBool::new(false),
        hash_fn: UnsafeCell::new(None),
    };

    pub fn set_soroban_hash_backend(hash_fn: fn(&[u8]) -> [u8; 32]) {
        unsafe {
            *SOROBAN_HASH.hash_fn.get() = Some(hash_fn);
        }
        SOROBAN_HASH.initialized.store(true, Ordering::Release);
    }

    #[inline(always)]
    pub fn is_initialized() -> bool {
        SOROBAN_HASH.initialized.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub fn call_hash(data: &[u8]) -> [u8; 32] {
        unsafe {
            if let Some(f) = *SOROBAN_HASH.hash_fn.get() {
                f(data)
            } else {
                // Should never happen if properly initialized
                [0u8; 32]
            }
        }
    }
}

/// Compute the active backend hash of the given data
#[inline(always)]
pub fn hash32(data: &[u8]) -> [u8; 32] {
    // Pure Soroban (no_std + soroban-precompile, non-test): rely on host backend.
    #[cfg(all(feature = "soroban-precompile", not(feature = "std"), not(test)))]
    {
        if soroban_hash_backend::is_initialized() {
            return soroban_hash_backend::call_hash(data);
        }
        // Fallback - should not happen in properly initialized Soroban contract
        [0u8; 32]
    }

    // All other configurations (including tests) use the built-in Keccak backend.
    #[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
    {
        KECCAK_BACKEND.hash(data)
    }
}

#[cfg(all(feature = "soroban-precompile", not(feature = "std"), not(test)))]
pub use soroban_hash_backend::set_soroban_hash_backend;
