use ark_bn254::Fr as ArkFr;
use ark_ff::BigInteger256;
use ark_ff::{Field, PrimeField, Zero};
use core::ops::{Add, Mul, Neg, Sub};

/// Maximum hex string length we support (64 chars + 2 for "0x" prefix)
const MAX_HEX_LEN: usize = 66;

/// Normalize hex string to fixed buffer and return slice
/// Handles 0x prefix and odd-length hex strings
#[inline(always)]
fn decode_hex_to_bytes(s: &str, out: &mut [u8; 32]) -> usize {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let raw = raw.strip_prefix("0X").unwrap_or(raw);

    // Use a fixed buffer for hex normalization
    let mut hex_buf = [0u8; MAX_HEX_LEN];
    let raw_bytes = raw.as_bytes();
    let raw_len = raw_bytes.len().min(64); // Max 64 hex chars for 32 bytes

    // If odd length, prepend a '0'
    let (hex_slice, hex_len) = if raw_len & 1 == 1 {
        hex_buf[0] = b'0';
        hex_buf[1..=raw_len].copy_from_slice(&raw_bytes[..raw_len]);
        (&hex_buf[..raw_len + 1], raw_len + 1)
    } else {
        hex_buf[..raw_len].copy_from_slice(&raw_bytes[..raw_len]);
        (&hex_buf[..raw_len], raw_len)
    };

    // Decode hex to bytes
    let byte_len = hex_len / 2;
    let mut temp = [0u8; 32];
    for i in 0..byte_len {
        let hi = hex_char_to_nibble(hex_slice[i * 2]);
        let lo = hex_char_to_nibble(hex_slice[i * 2 + 1]);
        temp[i] = (hi << 4) | lo;
    }

    // Pad to 32 bytes (right-aligned, big-endian)
    let offset = 32 - byte_len;
    out[offset..].copy_from_slice(&temp[..byte_len]);

    byte_len
}

#[inline(always)]
fn hex_char_to_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0, // Invalid char treated as 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    /// Construct from u64.
    pub fn from_u64(x: u64) -> Self {
        Fr(ArkFr::from(x))
    }

    /// Construct from hex string (with or without 0x prefix).
    /// Normalize to even digits before decoding so OddLength exception won't occur.
    pub fn from_str(s: &str) -> Self {
        let mut padded = [0u8; 32];
        decode_hex_to_bytes(s, &mut padded);
        Self::from_bytes(&padded)
    }

    /// Construct from a 32-byte big-endian array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // ark-ff takes LE (little-endian) so BE → LE
        let mut tmp = *bytes;
        tmp.reverse();
        Fr(ArkFr::from_le_bytes_mod_order(&tmp))
    }

    /// Convert to 32-byte big-endian representation.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        let bi: BigInteger256 = self.0.into_bigint();
        let mut out = [0u8; 32];
        for (i, limb) in bi.0.iter().rev().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Fr)
    }

    pub fn zero() -> Self {
        Fr(ArkFr::zero())
    }

    pub fn one() -> Self {
        Fr(ArkFr::ONE)
    }

    pub fn pow(&self, exp: u128) -> Self {
        let mut bits = [0u64; 4];
        bits[0] = exp as u64;
        Fr(self.0.pow(bits))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for Fr {
    type Output = Fr;
    fn add(self, rhs: Fr) -> Fr {
        Fr(self.0 + rhs.0)
    }
}

impl Sub for Fr {
    type Output = Fr;
    fn sub(self, rhs: Fr) -> Fr {
        Fr(self.0 - rhs.0)
    }
}

impl Mul for Fr {
    type Output = Fr;
    fn mul(self, rhs: Fr) -> Fr {
        Fr(self.0 * rhs.0)
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}
