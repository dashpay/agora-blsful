//! Legacy serialization implementation for G1 and G2 points

use crate::impls::inner_types::*;
use crate::traits::LegacyG1Point;
use crate::traits::LegacyG2Point;
use crate::BlsError;

/// Convert between legacy and modern G1 serialization formats
impl LegacyG1Point for G1Projective {
    fn serialize_g1(&self, legacy: bool) -> [u8; 48] {
        // Get the standard compressed serialization
        let bytes = self.to_affine().to_compressed();
        
        if !legacy {
            // Modern format - return as is
            return bytes;
        }
        
        // Convert to legacy format
        let mut legacy_bytes = bytes;
        
        // Check for infinity point (same in both formats)
        if legacy_bytes[0] == 0xc0 {
            return legacy_bytes;
        }
        
        // Extract y-coordinate sign from modern format (bit 5)
        let y_sign = (legacy_bytes[0] & 0x20) != 0;
        
        // Clear modern format bits (top 3 bits)
        legacy_bytes[0] &= 0x1f;
        
        // Set legacy y-coordinate sign (bit 7)
        if y_sign {
            legacy_bytes[0] |= 0x80;
        }
        
        legacy_bytes
    }
    
    fn deserialize_g1(bytes: &[u8; 48], legacy: bool) -> Result<Self, BlsError> {
        if !legacy {
            // Modern format - validate format before deserialization
            if bytes[0] != 0xc0 {  // Not infinity
                // Modern format requires bit 7 set (compression) and bit 6 clear
                if (bytes[0] & 0xc0) != 0x80 {
                    return Err(BlsError::DeserializationError(
                        format!("Invalid modern G1 format: byte[0] = 0x{:02x}, expected bit pattern 10xxxxxx", bytes[0])
                    ));
                }
            }
            
            // Modern format - use standard deserialization
            let opt = G1Affine::from_compressed(bytes);
            return Option::<G1Affine>::from(opt)
                .map(Into::into)
                .ok_or_else(|| BlsError::DeserializationError("Invalid G1 point".to_string()));
        }
        
        // Convert from legacy format
        let mut modern_bytes = *bytes;
        
        // Check for infinity point (same in both formats)
        if modern_bytes[0] == 0xc0 {
            let opt = G1Affine::from_compressed(&modern_bytes);
            return Option::<G1Affine>::from(opt)
                .map(Into::into)
                .ok_or_else(|| BlsError::DeserializationError("Invalid infinity point".to_string()));
        }
        
        // Extract y-coordinate sign from legacy format (bit 7)
        let y_sign = (modern_bytes[0] & 0x80) != 0;
        
        // Clear legacy bits
        modern_bytes[0] &= 0x7f;
        
        // Validate that no other high bits are set
        // In legacy format, after extracting Y bit (bit 7), only lower 5 bits should be used
        if modern_bytes[0] & 0xe0 != 0 {
            return Err(BlsError::LegacyFormatError(
                format!("Invalid legacy G1 format: unexpected bits in byte[0] = 0x{:02x}", bytes[0])
            ));
        }
        
        // Set modern format bits
        modern_bytes[0] |= 0x80;  // Compression bit
        if y_sign {
            modern_bytes[0] |= 0x20;  // Y-coordinate sign in modern position
        }
        
        let opt = G1Affine::from_compressed(&modern_bytes);
        Option::<G1Affine>::from(opt)
            .map(Into::into)
            .ok_or_else(|| BlsError::DeserializationError("Invalid G1 point after conversion".to_string()))
    }
}

/// Convert between legacy and modern G2 serialization formats
impl LegacyG2Point for G2Projective {
    fn serialize_g2(&self, legacy: bool) -> [u8; 96] {
        // Get the standard compressed serialization
        let bytes = self.to_affine().to_compressed();
        
        if !legacy {
            // Modern format - return as is
            return bytes;
        }
        
        // Convert to legacy format
        let mut legacy_bytes = bytes;
        
        // Check for infinity point (same in both formats)
        if legacy_bytes[0] == 0xc0 {
            return legacy_bytes;
        }
        
        // Extract y-coordinate sign from modern format (bit 5)
        let y_sign = (legacy_bytes[0] & 0x20) != 0;
        
        // Clear modern format bits (top 3 bits)
        legacy_bytes[0] &= 0x1f;
        
        // Set legacy y-coordinate sign (bit 7)
        if y_sign {
            legacy_bytes[0] |= 0x80;
        }
        
        legacy_bytes
    }
    
    fn deserialize_g2(bytes: &[u8; 96], legacy: bool) -> Result<Self, BlsError> {
        if !legacy {
            // Modern format - validate format before deserialization
            if bytes[0] != 0xc0 {  // Not infinity
                // Modern format requires bit 7 set (compression) and bit 6 clear
                if (bytes[0] & 0xc0) != 0x80 {
                    return Err(BlsError::DeserializationError(
                        format!("Invalid modern G2 format: byte[0] = 0x{:02x}, expected bit pattern 10xxxxxx", bytes[0])
                    ));
                }
            }
            
            // Modern format - use standard deserialization
            let opt = G2Affine::from_compressed(bytes);
            return Option::<G2Affine>::from(opt)
                .map(Into::into)
                .ok_or_else(|| BlsError::DeserializationError("Invalid G2 point".to_string()));
        }
        
        // Convert from legacy format
        let mut modern_bytes = *bytes;
        
        // Check for infinity point (same in both formats)
        if modern_bytes[0] == 0xc0 {
            let opt = G2Affine::from_compressed(&modern_bytes);
            return Option::<G2Affine>::from(opt)
                .map(Into::into)
                .ok_or_else(|| BlsError::DeserializationError("Invalid infinity point".to_string()));
        }
        
        // Extract y-coordinate sign from legacy format (bit 7)
        let y_sign = (modern_bytes[0] & 0x80) != 0;
        
        // Clear legacy bits
        modern_bytes[0] &= 0x7f;
        
        // Validate that no other high bits are set
        // In legacy format, after extracting Y bit (bit 7), only lower 5 bits should be used
        if modern_bytes[0] & 0xe0 != 0 {
            return Err(BlsError::LegacyFormatError(
                format!("Invalid legacy G2 format: unexpected bits in byte[0] = 0x{:02x}", bytes[0])
            ));
        }
        
        // Set modern format bits
        modern_bytes[0] |= 0x80;  // Compression bit
        if y_sign {
            modern_bytes[0] |= 0x20;  // Y-coordinate sign in modern position
        }
        
        let opt = G2Affine::from_compressed(&modern_bytes);
        Option::<G2Affine>::from(opt)
            .map(Into::into)
            .ok_or_else(|| BlsError::DeserializationError("Invalid G2 point after conversion".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_g1_legacy_roundtrip() {
        // Test with a non-identity point
        let point = G1Projective::generator();
        
        // Test modern format roundtrip
        let modern_bytes = point.serialize_g1(false);
        let restored_modern = G1Projective::deserialize_g1(&modern_bytes, false).unwrap();
        assert_eq!(point, restored_modern);
        
        // Test legacy format roundtrip
        let legacy_bytes = point.serialize_g1(true);
        let restored_legacy = G1Projective::deserialize_g1(&legacy_bytes, true).unwrap();
        assert_eq!(point, restored_legacy);
        
        // Verify formats are different
        assert_ne!(modern_bytes[0], legacy_bytes[0]);
    }
    
    #[test]
    fn test_g1_infinity_same_format() {
        let infinity = G1Projective::identity();
        
        let modern_bytes = infinity.serialize_g1(false);
        let legacy_bytes = infinity.serialize_g1(true);
        
        // Infinity should be the same in both formats
        assert_eq!(modern_bytes, legacy_bytes);
        assert_eq!(modern_bytes[0], 0xc0);
    }
    
    #[test]
    fn test_g2_legacy_roundtrip() {
        // Test with a non-identity point
        let point = G2Projective::generator();
        
        // Test modern format roundtrip
        let modern_bytes = point.serialize_g2(false);
        let restored_modern = G2Projective::deserialize_g2(&modern_bytes, false).unwrap();
        assert_eq!(point, restored_modern);
        
        // Test legacy format roundtrip
        let legacy_bytes = point.serialize_g2(true);
        let restored_legacy = G2Projective::deserialize_g2(&legacy_bytes, true).unwrap();
        assert_eq!(point, restored_legacy);
        
        // Verify formats are different
        assert_ne!(modern_bytes[0], legacy_bytes[0]);
    }
    
    #[test]
    fn test_cross_format_error() {
        // Test that the formats produce different serializations
        let point = G1Projective::generator();
        
        let modern_bytes = point.serialize_g1(false);
        let legacy_bytes = point.serialize_g1(true);
        
        // The formats should produce different bytes (at least the first byte)
        assert_ne!(modern_bytes[0], legacy_bytes[0], "Formats should differ");
        
        // Test with a point that will have Y=0 in legacy format
        // This is a specific test case that should fail cross-format deserialization
        for i in 1..20u64 {
            let scalar = <G1Projective as Group>::Scalar::from(i);
            let test_point = G1Projective::generator() * scalar;
            let test_legacy = test_point.serialize_g1(true);
            
            if (test_legacy[0] & 0x80) == 0 {
                // Found Y=0 case - this should fail modern deserialization
                let result = G1Projective::deserialize_g1(&test_legacy, false);
                assert!(result.is_err(), "Legacy Y=0 should fail modern deser");
                break;
            }
        }
    }
}