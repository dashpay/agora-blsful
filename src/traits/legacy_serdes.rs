//! Legacy serialization support for BLS signatures
//!
//! This module provides support for the legacy serialization format used by
//! older BLS implementations, particularly for Dash compatibility.

/// Trait for types that support both legacy and modern serialization formats
pub trait LegacySerialize: Sized {
    /// Serialize with legacy format support
    ///
    /// # Arguments
    /// * `legacy` - If true, uses legacy format; if false, uses modern format
    fn serialize_with_mode(&self, legacy: bool) -> Vec<u8>;

    /// Deserialize with legacy format support
    ///
    /// # Arguments
    /// * `bytes` - The bytes to deserialize
    /// * `legacy` - If true, expects legacy format; if false, expects modern format
    fn deserialize_with_mode(bytes: &[u8], legacy: bool) -> Result<Self, crate::BlsError>;
}

/// Trait for G1 point serialization with legacy support (48 bytes)
pub trait LegacyG1Point: Sized {
    /// Serialize G1 point with format selection
    fn serialize_g1(&self, legacy: bool) -> [u8; 48];

    /// Deserialize G1 point with format selection
    fn deserialize_g1(bytes: &[u8; 48], legacy: bool) -> Result<Self, crate::BlsError>;
}

/// Trait for G2 point serialization with legacy support (96 bytes)
pub trait LegacyG2Point: Sized {
    /// Serialize G2 point with format selection
    fn serialize_g2(&self, legacy: bool) -> [u8; 96];

    /// Deserialize G2 point with format selection
    fn deserialize_g2(bytes: &[u8; 96], legacy: bool) -> Result<Self, crate::BlsError>;
}
