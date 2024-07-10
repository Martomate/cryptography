#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BigUint {
    bytes: Vec<u8>,
    bits_used: u32,
}

impl BigUint {
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Self {
        let bytes: Vec<u8> = bytes
            .as_ref()
            .iter()
            .skip_while(|&&n| n == 0)
            .cloned()
            .collect();
        let bits_used = (bytes.len() - 1) as u32 * 8
            + (if bytes[0] == 0 {
                0
            } else {
                bytes[0].ilog2() + 1
            });
        Self { bytes, bits_used }
    }

    pub fn as_u128(&self) -> Result<u128, String> {
        if self.bytes.len() > 16 {
            return Err(format!(
                "expected at most 16 bytes, but got {}",
                self.bytes.len()
            ));
        }
        let mut bytes = [0; 16];
        bytes[(16 - self.bytes.len())..].copy_from_slice(&self.bytes);
        Ok(<u128>::from_be_bytes(bytes))
    }

    pub fn bits_used(&self) -> u32 {
        self.bits_used
    }

    pub fn is_set(&self, idx: u32) -> bool {
        let byte_idx = self.bytes.len() - 1 - (idx / 8) as usize;
        let bit_idx = idx % 8;
        (self.bytes[byte_idx] >> bit_idx) & 1 != 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<u128> for BigUint {
    fn from(value: u128) -> Self {
        let bytes = value.to_be_bytes();
        let bytes = bytes.into_iter().skip_while(|&n| n == 0).collect();
        Self {
            bytes,
            bits_used: if value == 0 { 0 } else { value.ilog2() + 1 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u128() {
        #[rustfmt::skip]
        assert_eq!(
            BigUint::from(0x1234_5678_9012_3456_7890_u128),
            BigUint { bytes: vec![
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ], bits_used: 10 * 8 - 3 },
        );
    }

    #[test]
    fn to_u128_small_enough() {
        #[rustfmt::skip]
        assert_eq!(
            BigUint { bytes: vec![
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ], bits_used: 10 * 8 - 3 }.as_u128(),
            Ok(0x1234_5678_9012_3456_7890_u128),
        );
    }

    #[test]
    fn to_u128_too_big() {
        #[rustfmt::skip]
        assert_eq!(
            BigUint { bytes: vec![
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
                0x12, 0x34, 0x56, 0x78,
                0x90, 0x12, 0x34, 0x56,
            ], bits_used: 18 * 8 - 3 }
            .as_u128(),
            Err("expected at most 16 bytes, but got 18".to_string()),
        );
    }

    #[test]
    fn from_bytes_trails_leading_zeros() {
        #[rustfmt::skip]
        assert_eq!(
            BigUint::from_bytes([
                0x00, 0x00, 0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ]),
            BigUint { bytes: vec![
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ], bits_used: 10 * 8 - 3 },
        );
    }
}
