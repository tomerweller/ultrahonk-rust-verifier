//! Error types for the UltraHonk verifier (no heap allocation)

/// Error codes for verification failures.
/// Using u32 codes instead of String messages to avoid heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifierError {
    // Sumcheck errors (100-199)
    /// Sumcheck round failed: sum of univariate != target
    SumcheckRoundFailed = 100,
    /// Sumcheck barycentric denominator is zero
    SumcheckDenomZero = 101,
    /// Sumcheck final relation sum mismatch
    SumcheckFinalMismatch = 102,

    // Shplemini/Shplonk errors (200-299)
    /// Shplonk denominator (z - r^i) is zero
    ShplonkDenomPosZero = 200,
    /// Shplonk denominator (z + r^i) is zero
    ShplonkDenomNegZero = 201,
    /// Gemini r challenge is zero (cannot invert)
    GeminiRZero = 202,
    /// Fold round denominator is zero
    FoldRoundDenomZero = 203,
    /// Shplonk pairing check failed
    ShplonkPairingFailed = 204,

    // Input validation errors (300-399)
    /// Public inputs must be 32-byte aligned
    PublicInputsNotAligned = 300,
    /// VK public inputs size < 16 (pairing points)
    VkInputsTooSmall = 301,
    /// Public inputs count mismatch
    PublicInputsMismatch = 302,
    /// Public input delta denominator is zero
    PublicInputDeltaDenomZero = 303,

    // EC/MSM errors (400-499)
    /// MSM length mismatch between points and scalars
    MsmLengthMismatch = 400,
    /// Soroban EC backend not initialized
    EcBackendNotInitialized = 401,
    /// Soroban hash backend not initialized
    HashBackendNotInitialized = 402,
    /// Point validation failed
    PointValidationFailed = 403,
}

impl VerifierError {
    /// Get a short description of the error (const, no allocation)
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SumcheckRoundFailed => "sumcheck round failed",
            Self::SumcheckDenomZero => "sumcheck denom zero",
            Self::SumcheckFinalMismatch => "sumcheck final mismatch",
            Self::ShplonkDenomPosZero => "shplonk denom pos zero",
            Self::ShplonkDenomNegZero => "shplonk denom neg zero",
            Self::GeminiRZero => "gemini_r zero",
            Self::FoldRoundDenomZero => "fold round denom zero",
            Self::ShplonkPairingFailed => "shplonk pairing failed",
            Self::PublicInputsNotAligned => "public inputs not aligned",
            Self::VkInputsTooSmall => "vk inputs too small",
            Self::PublicInputsMismatch => "public inputs mismatch",
            Self::PublicInputDeltaDenomZero => "public input delta denom zero",
            Self::MsmLengthMismatch => "msm length mismatch",
            Self::EcBackendNotInitialized => "ec backend not initialized",
            Self::HashBackendNotInitialized => "hash backend not initialized",
            Self::PointValidationFailed => "point validation failed",
        }
    }

    /// Get the numeric error code
    pub const fn code(&self) -> u32 {
        *self as u32
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.as_str(), self.code())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifierError {}
