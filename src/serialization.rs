
/// Serialization format for BLS signatures and public keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// Legacy format - y-coordinate sign in bit 7
    Legacy,
    /// Modern IETF format - y-coordinate sign in bit 5
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

impl Default for SerializationFormat {
    fn default() -> Self {
        SerializationFormat::Modern
    }
}
