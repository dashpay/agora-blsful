//! Legacy serialization implementation for G1 and G2 points

use crate::impls::inner_types::*;
use crate::traits::LegacyG1Point;
use crate::traits::LegacyG2Point;
use crate::{BlsError, SerializationFormat};

/// Common bit manipulation constants for legacy serialization
const INFINITY_BYTE: u8 = 0xc0;
const MODERN_Y_SIGN_BIT: u8 = 0x20; // Bit 5
const LEGACY_Y_SIGN_BIT: u8 = 0x80; // Bit 7
const MODERN_COMPRESSION_BIT: u8 = 0x80; // Bit 7
const MODERN_FORMAT_MASK: u8 = 0x1f; // Clear top 3 bits
const LEGACY_FORMAT_MASK: u8 = 0x7f; // Clear bit 7
const LEGACY_VALIDATION_MASK: u8 = 0xe0; // Check bits 5-7 are clear

/// Convert from modern to legacy format for compressed point serialization
#[inline]
fn modern_to_legacy_format(bytes: &mut [u8]) {
    // Check for infinity point (same in both formats)
    if bytes[0] == INFINITY_BYTE {
        return;
    }

    // Extract y-coordinate sign from modern format (bit 5)
    let y_sign = (bytes[0] & MODERN_Y_SIGN_BIT) != 0;

    // Clear modern format bits (top 3 bits)
    bytes[0] &= MODERN_FORMAT_MASK;

    // Set legacy y-coordinate sign (bit 7)
    if y_sign {
        bytes[0] |= LEGACY_Y_SIGN_BIT;
    }
}

/// Convert from legacy to modern format for compressed point deserialization
#[inline]
fn legacy_to_modern_format(bytes: &mut [u8]) -> Result<(), BlsError> {
    // Check for infinity point (same in both formats)
    if bytes[0] == INFINITY_BYTE {
        return Ok(());
    }

    // Extract y-coordinate sign from legacy format (bit 7)
    let y_sign = (bytes[0] & LEGACY_Y_SIGN_BIT) != 0;

    // Clear legacy bits
    bytes[0] &= LEGACY_FORMAT_MASK;

    // Validate that no other high bits are set
    // In legacy format, after extracting Y bit (bit 7), only lower 5 bits should be used
    if bytes[0] & LEGACY_VALIDATION_MASK != 0 {
        return Err(BlsError::LegacyFormatError(format!(
            "Invalid legacy format: unexpected bits in byte[0] = 0x{:02x}",
            bytes[0] | (if y_sign { LEGACY_Y_SIGN_BIT } else { 0 }) // Show original byte
        )));
    }

    // Set modern format bits
    bytes[0] |= MODERN_COMPRESSION_BIT; // Compression bit
    if y_sign {
        bytes[0] |= MODERN_Y_SIGN_BIT; // Y-coordinate sign in modern position
    }

    Ok(())
}

/// Validate modern format header byte
#[inline]
fn validate_modern_format(byte0: u8, point_type: &str) -> Result<(), BlsError> {
    if byte0 != INFINITY_BYTE {
        // Not infinity
        // Modern format requires bit 7 set (compression) and bit 6 clear
        if (byte0 & 0xc0) != 0x80 {
            return Err(BlsError::DeserializationError(
                format!("Invalid modern {} format: byte[0] = 0x{:02x}, expected bit pattern 10xxxxxx", point_type, byte0)
            ));
        }
    }
    Ok(())
}

/// Convert between legacy and modern G1 serialization formats
impl LegacyG1Point for G1Projective {
    fn serialize_g1(&self, format: SerializationFormat) -> [u8; 48] {
        // Get the standard compressed serialization
        let bytes = self.to_affine().to_compressed();

        match format {
            SerializationFormat::Modern => bytes,
            SerializationFormat::Legacy => {
                let mut legacy_bytes = bytes;
                modern_to_legacy_format(&mut legacy_bytes);
                legacy_bytes
            }
        }
    }

    fn deserialize_g1(bytes: &[u8; 48], format: SerializationFormat) -> Result<Self, BlsError> {
        match format {
            SerializationFormat::Modern => {
                // Validate modern format
                validate_modern_format(bytes[0], "G1")?;

                // Modern format - use standard deserialization
                let opt = G1Affine::from_compressed(bytes);
                Option::<G1Affine>::from(opt)
                    .map(Into::into)
                    .ok_or_else(|| BlsError::DeserializationError("Invalid G1 point".to_string()))
            }
            SerializationFormat::Legacy => {
                // Convert from legacy format
                let mut modern_bytes = *bytes;
                legacy_to_modern_format(&mut modern_bytes)?;

                let opt = G1Affine::from_compressed(&modern_bytes);
                Option::<G1Affine>::from(opt)
                    .map(Into::into)
                    .ok_or_else(|| {
                        BlsError::DeserializationError("Invalid G1 point after conversion".to_string())
                    })
            }
        }
    }
}

/// Convert between legacy and modern G2 serialization formats
impl LegacyG2Point for G2Projective {
    fn serialize_g2(&self, format: SerializationFormat) -> [u8; 96] {
        // Get the standard compressed serialization
        let bytes = self.to_affine().to_compressed();

        match format {
            SerializationFormat::Modern => bytes,
            SerializationFormat::Legacy => {
                let mut legacy_bytes = bytes;
                modern_to_legacy_format(&mut legacy_bytes);
                legacy_bytes
            }
        }
    }

    fn deserialize_g2(bytes: &[u8; 96], format: SerializationFormat) -> Result<Self, BlsError> {
        match format {
            SerializationFormat::Modern => {
                // Validate modern format
                validate_modern_format(bytes[0], "G2")?;

                // Modern format - use standard deserialization
                let opt = G2Affine::from_compressed(bytes);
                Option::<G2Affine>::from(opt)
                    .map(Into::into)
                    .ok_or_else(|| BlsError::DeserializationError("Invalid G2 point".to_string()))
            }
            SerializationFormat::Legacy => {
                // Convert from legacy format
                let mut modern_bytes = *bytes;
                legacy_to_modern_format(&mut modern_bytes)?;

                let opt = G2Affine::from_compressed(&modern_bytes);
                Option::<G2Affine>::from(opt)
                    .map(Into::into)
                    .ok_or_else(|| {
                        BlsError::DeserializationError("Invalid G2 point after conversion".to_string())
                    })
            }
        }
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
        let modern_bytes = point.serialize_g1(SerializationFormat::Modern);
        let restored_modern = G1Projective::deserialize_g1(&modern_bytes, SerializationFormat::Modern).unwrap();
        assert_eq!(point, restored_modern);

        // Test legacy format roundtrip
        let legacy_bytes = point.serialize_g1(SerializationFormat::Legacy);
        let restored_legacy = G1Projective::deserialize_g1(&legacy_bytes, SerializationFormat::Legacy).unwrap();
        assert_eq!(point, restored_legacy);

        // Verify formats are different
        assert_ne!(modern_bytes[0], legacy_bytes[0]);
    }

    #[test]
    fn test_g1_infinity_same_format() {
        let infinity = G1Projective::identity();

        let modern_bytes = infinity.serialize_g1(SerializationFormat::Modern);
        let legacy_bytes = infinity.serialize_g1(SerializationFormat::Legacy);

        // Infinity should be the same in both formats
        assert_eq!(modern_bytes, legacy_bytes);
        assert_eq!(modern_bytes[0], 0xc0);
    }

    #[test]
    fn test_g2_legacy_roundtrip() {
        // Test with a non-identity point
        let point = G2Projective::generator();

        // Test modern format roundtrip
        let modern_bytes = point.serialize_g2(SerializationFormat::Modern);
        let restored_modern = G2Projective::deserialize_g2(&modern_bytes, SerializationFormat::Modern).unwrap();
        assert_eq!(point, restored_modern);

        // Test legacy format roundtrip
        let legacy_bytes = point.serialize_g2(SerializationFormat::Legacy);
        let restored_legacy = G2Projective::deserialize_g2(&legacy_bytes, SerializationFormat::Legacy).unwrap();
        assert_eq!(point, restored_legacy);

        // Verify formats are different
        assert_ne!(modern_bytes[0], legacy_bytes[0]);
    }

    #[test]
    fn test_cross_format_error() {
        // Test that the formats produce different serializations
        let point = G1Projective::generator();

        let modern_bytes = point.serialize_g1(SerializationFormat::Modern);
        let legacy_bytes = point.serialize_g1(SerializationFormat::Legacy);

        // The formats should produce different bytes (at least the first byte)
        assert_ne!(modern_bytes[0], legacy_bytes[0], "Formats should differ");

        // Test with a point that has a negative Y-coordinate sign (bit 7 = 0 in legacy format)
        // This bit pattern causes the serialized value to fail modern format validation
        // due to the incorrect bit prefix
        for i in 1..20u64 {
            let scalar = <G1Projective as Group>::Scalar::from(i);
            let test_point = G1Projective::generator() * scalar;
            let test_legacy = test_point.serialize_g1(SerializationFormat::Legacy);

            if (test_legacy[0] & 0x80) == 0 {
                // Found Y=0 case - this should fail modern deserialization
                let result = G1Projective::deserialize_g1(&test_legacy, SerializationFormat::Modern);
                assert!(result.is_err(), "Legacy Y=0 should fail modern deser");
                break;
            }
        }
    }
}
