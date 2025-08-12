
/// Serialization format for BLS signatures and public keys
///
/// This enum specifies whether to use the modern IETF standard format or
/// the legacy format compatible with older implementations (e.g., Dash).
///
/// # Format Differences
/// - **Modern**: Y-coordinate sign bit is stored in bit 5 (IETF standard)
/// - **Legacy**: Y-coordinate sign bit is stored in bit 7 (Dash-compatible)
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SerializationFormat {
    /// Legacy format - y-coordinate sign in bit 7
    Legacy,
    /// Modern IETF format - y-coordinate sign in bit 5
    #[default]
    Modern,
}

impl SerializationFormat {
    /// Returns true if this is the legacy format
    pub fn is_legacy(&self) -> bool {
        matches!(self, SerializationFormat::Legacy)
    }
    
    /// Returns true if this is the modern format
    pub fn is_modern(&self) -> bool {
        matches!(self, SerializationFormat::Modern)
    }
}

