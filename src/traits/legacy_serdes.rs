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

/// Serialization format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// Legacy format (Dash-compatible)
    Legacy,
    /// Modern format (IETF standard)
    Modern,
    /// Could be either format (e.g., infinity point)
    Either,
    /// Cannot determine format
    Unknown,
}

impl SerializationFormat {
    /// Detect the serialization format from G1 point bytes
    pub fn detect_g1(bytes: &[u8]) -> Self {
        if bytes.len() < 1 {
            return Self::Unknown;
        }

        // Infinity point (same in both formats)
        if bytes[0] == 0xc0 {
            return Self::Either;
        }

        // Check compression bit (bit 7)
        if bytes[0] & 0x80 != 0 {
            // Bit 7 set - modern format (compressed) or legacy Y=1
            if bytes[0] & 0x40 != 0 {
                // Bit 6 also set - invalid for normal points
                return Self::Unknown;
            }
            // Need more context to determine
            return Self::Unknown;
        } else {
            // Bit 7 not set - definitely legacy Y=0
            return Self::Legacy;
        }
    }

    /// Detect the serialization format from G2 point bytes
    pub fn detect_g2(bytes: &[u8]) -> Self {
        // G2 detection follows same pattern as G1
        Self::detect_g1(bytes)
    }
}

/// Configuration for serialization behavior
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SerializationConfig {
    /// Use legacy serialization format
    pub legacy: bool,
}

impl Default for SerializationConfig {
    fn default() -> Self {
        Self { legacy: false }
    }
}

impl SerializationConfig {
    /// Legacy configuration (Dash-compatible)
    pub const LEGACY: Self = Self { legacy: true };

    /// Modern configuration (IETF standard)
    pub const MODERN: Self = Self { legacy: false };
}
