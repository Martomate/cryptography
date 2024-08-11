use std::ops::{Add, Rem, Shl, Shr};

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

        let mut bits_used = 0;
        if !bytes.is_empty() {
            bits_used += (bytes.len() - 1) as u32 * 8;
            bits_used += bytes[0].ilog2() + 1;
        }
        Self { bytes, bits_used }
    }

    fn from_u128(value: u128) -> Self {
        let bytes = value.to_be_bytes();
        let bytes = bytes.into_iter().skip_while(|&n| n == 0).collect();
        Self {
            bytes,
            bits_used: if value == 0 { 0 } else { value.ilog2() + 1 },
        }
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
        if self.bytes.is_empty() {
            return false;
        }
        let byte_idx = self.bytes.len() - 1 - (idx / 8) as usize;
        if byte_idx >= self.bytes.len() {
            return false;
        }
        let bit_idx = idx % 8;
        (self.bytes[byte_idx] >> bit_idx) & 1 != 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<u128> for BigUint {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl Add<&BigUint> for BigUint {
    type Output = BigUint;

    fn add(self, rhs: &BigUint) -> BigUint {
        let mut dest: Vec<u8> = (0..(self.bytes.len().max(rhs.bytes.len()) + 1))
            .map(|_| 0)
            .collect();

        {
            let l = &self.bytes;
            let r = &rhs.bytes;

            let l_len = l.len();
            let r_len = r.len();
            let d_len = dest.len();

            for i in 0..d_len - 1 {
                let mut sum = 0_u16;
                sum += dest[d_len - 1 - i] as u16;
                if i < l_len {
                    sum += l[l_len - 1 - i] as u16;
                }
                if i < r_len {
                    sum += r[r_len - 1 - i] as u16;
                }
                dest[d_len - 1 - i] = (sum & 0xff) as u8;
                dest[d_len - 2 - i] = ((sum >> 8) & 0xff) as u8;
            }
        }

        BigUint::from_bytes(dest)
    }
}

impl Rem<&BigUint> for BigUint {
    type Output = BigUint;

    fn rem(self, rhs: &BigUint) -> BigUint {
        if rhs.bits_used > self.bits_used {
            return self;
        }
        // TODO: implement using comparison and subtraction
        BigUint::from_u128(self.as_u128().unwrap() % rhs.as_u128().unwrap())
    }
}

impl Shl<u32> for BigUint {
    type Output = BigUint;

    fn shl(self, rhs: u32) -> BigUint {
        // add whole 0-bytes if possible
        if rhs >= 8 {
            let steps = rhs / 8;
            let bits = steps * 8;

            // shift the rest first
            let mut result = self.shl(rhs - bits);

            result.bytes.extend((0..steps).map(|_| 0));
            result.bits_used += bits;
            result
        } else {
            let mut result: Vec<u8> = (0..self.bytes.len() + 1).map(|_| 0).collect();
            for i in (0..self.bytes.len()).rev() {
                result[i + 1] |= self.bytes[i] << rhs;
                result[i] = self.bytes[i] >> (8 - rhs);
            }
            BigUint::from_bytes(result)
        }
    }
}

impl Shr<u32> for BigUint {
    type Output = BigUint;

    fn shr(self, rhs: u32) -> BigUint {
        if rhs == 0 {
            return self;
        }
        let mut result: Vec<u8> = (0..self.bytes.len()).map(|_| 0).collect();
        for i in 0..self.bytes.len() {
            result[i] |= self.bytes[i] >> 1;
            if i < self.bytes.len() - 1 {
                result[i + 1] = self.bytes[i] << (8 - 1);
            }
        }

        BigUint::from_bytes(result).shr(rhs - 1)
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
