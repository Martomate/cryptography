use std::{
    cmp::Ordering, iter, ops::{Add, Rem, Shl, Shr, Sub}
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BigUint {
    bytes: Vec<u8>,
}

impl BigUint {
    pub fn from_be_bytes<B: AsRef<[u8]>>(bytes: B) -> Self {
        let bytes = bytes.as_ref();
        let Some(num_leading_zeros) = bytes.iter().position(|&n| n != 0) else {
            return Self::from_u128(0);
        };
        let bytes = &bytes[num_leading_zeros..];

        Self { bytes: bytes.iter().rev().cloned().collect() }
    }
    
    pub fn from_le_bytes<B: AsRef<[u8]>>(bytes: B) -> Self {
        let mut bytes: Vec<u8> = bytes.as_ref().to_vec();

        while let Some(&b) = bytes.last() {
            if b != 0 {
                break;
            }
            bytes.pop();
        }

        Self { bytes }
    }

    fn from_u128(value: u128) -> Self {
        if value == 0 {
            return Self {
                bytes: vec![],
            };
        }

        let bytes = value.to_le_bytes();
        let num_bytes = bytes.iter().rposition(|&n| n != 0).unwrap() + 1;
        Self { bytes: bytes[..num_bytes].to_owned() }
    }

    pub fn as_u128(&self) -> Result<u128, String> {
        if self.bytes.len() > 16 {
            return Err(format!(
                "expected at most 16 bytes, but got {}",
                self.bytes.len()
            ));
        }
        let mut bytes = [0; 16];
        bytes[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(<u128>::from_le_bytes(bytes))
    }

    pub fn bits_used(&self) -> u32 {
        if self.bytes.is_empty() {
            return 0;
        }

        let mut bits_used = 0;
        let last_idx = self.bytes.len() - 1;
        bits_used += last_idx as u32 * 8;
        bits_used += self.bytes[last_idx].ilog2() + 1;
        bits_used
    }

    pub fn is_set(&self, idx: u32) -> bool {
        if idx >= self.bits_used() {
            return false;
        }
        if self.bytes.is_empty() {
            return false;
        }
        let byte_idx = (idx / 8) as usize;
        if byte_idx >= self.bytes.len() {
            return false;
        }
        let bit_idx = idx % 8;
        (self.bytes[byte_idx] >> bit_idx) & 1 != 0
    }

    /** Note: after calling this function the bits_used field might be wrong */
    pub fn update(&mut self, idx: u32, set: bool) {
        if self.bytes.is_empty() {
            panic!("not enough space");
        }
        let byte_idx = (idx / 8) as usize;
        if byte_idx >= self.bytes.len() {
            panic!("not enough space");
        }
        let bit_idx = idx % 8;
        if set {
            self.bytes[byte_idx] |= 1 << bit_idx;
        } else {
            self.bytes[byte_idx] &= !(1 << bit_idx);
        }
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        self.bytes.iter().rev().cloned().collect()
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
                sum += dest[i] as u16;
                if i < l_len {
                    sum += l[i] as u16;
                }
                if i < r_len {
                    sum += r[i] as u16;
                }
                dest[i] = (sum & 0xff) as u8;
                dest[i+1] = ((sum >> 8) & 0xff) as u8;
            }
        }

        BigUint::from_le_bytes(dest)
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.bits_used().cmp(&other.bits_used()) {
            Ordering::Equal => {
                for i in (0..self.bits_used()).rev() {
                    let (a, b) = (self.is_set(i), other.is_set(i));
                    if a && !b {
                        return Ordering::Greater;
                    }
                    if !a && b {
                        return Ordering::Less;
                    }
                }
                Ordering::Equal
            }
            ord => ord,
        }
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Sub<&BigUint> for BigUint {
    type Output = BigUint;

    fn sub(self, rhs: &BigUint) -> Self::Output {
        // ensure there is enough space for the upcoming addition
        let mut inv = Vec::with_capacity(self.bytes.len() + 1);

        let offset = inv.capacity() - rhs.bytes.len();
        for i in 0..rhs.bytes.len() {
            inv.push(!rhs.bytes[i]);
        }
        for _ in 0..offset {
            inv.push(!0);
        }
        let mut res = BigUint::from_le_bytes(inv) + &BigUint::from_u128(1) + &self;

        for i in self.bits_used()..res.bits_used() {
            res.update(i, false);
        }

        BigUint::from_le_bytes(res.bytes)
    }
}

impl Rem<&BigUint> for BigUint {
    type Output = BigUint;

    fn rem(self, rhs: &BigUint) -> BigUint {
        if rhs.bits_used() > self.bits_used() {
            return self;
        }

        let d = self.bits_used() - rhs.bits_used();

        let mut rest = self.clone();
        let mut m = rhs.clone() << d;
        for _ in (0..=d).rev() {
            if m <= rest {
                rest = rest - &m;
            }
            m = m >> 1;
        }

        rest
    }
}

impl Shl<u32> for BigUint {
    type Output = BigUint;

    fn shl(self, rhs: u32) -> BigUint {
        // add whole 0-bytes if possible
        if rhs == 0 {
            self
        } else if rhs >= 8 {
            let steps = rhs / 8;
            let bits = steps * 8;

            // shift the rest first
            let mut result = self.shl(rhs - bits);

            result.bytes.splice(0..0, iter::repeat(0).take(steps as usize));
            result
        } else {
            let mut result: Vec<u8> = (0..self.bytes.len() + 1).map(|_| 0).collect();
            for i in 0..self.bytes.len() {
                result[i] |= self.bytes[i] << rhs;
                result[i + 1] = self.bytes[i] >> (8 - rhs);
            }
            BigUint::from_le_bytes(result)
        }
    }
}

impl Shr<u32> for BigUint {
    type Output = BigUint;

    fn shr(self, rhs: u32) -> BigUint {
        if rhs == 0 {
            return self;
        }
        if rhs >= 8 {
            let steps = rhs / 8;
            let bits = steps * 8;

            // shift the rest first
            let mut result = self.shr(rhs - bits);

            result.bytes.extend(iter::repeat(0).take(steps as usize));
            return result
        }
        let mut result: Vec<u8> = (0..self.bytes.len()).map(|_| 0).collect();
        for i in (0..self.bytes.len()).rev() {
            result[i] |= self.bytes[i] >> 1;
            if i > 0 {
                result[i - 1] = self.bytes[i] << (8 - 1);
            }
        }

        BigUint::from_le_bytes(result).shr(rhs - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u128() {
        let a = BigUint::from(0x1234_5678_9012_3456_7890_u128);
        #[rustfmt::skip]
        assert_eq!(
            a.to_be_bytes(),
            vec![
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ],
        );
        assert_eq!(a.bits_used(), 10 * 8 - 3);
    }

    #[test]
    fn to_u128_small_enough() {
        #[rustfmt::skip]
        assert_eq!(
            BigUint::from_be_bytes([
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ]).as_u128(),
            Ok(0x1234_5678_9012_3456_7890_u128),
        );
    }

    #[test]
    fn to_u128_too_big() {
        #[rustfmt::skip]
        assert_eq!(
            BigUint::from_be_bytes([
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
                0x12, 0x34, 0x56, 0x78,
                0x90, 0x12, 0x34, 0x56,
            ]).as_u128(),
            Err("expected at most 16 bytes, but got 18".to_string()),
        );
    }

    #[test]
    fn from_bytes_trails_leading_zeros() {
        #[rustfmt::skip]
        assert_eq!(
            BigUint::from_be_bytes([
                0x00, 0x00, 0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ]).to_be_bytes(),
            vec![
                            0x12, 0x34,
                0x56, 0x78, 0x90, 0x12,
                0x34, 0x56, 0x78, 0x90,
            ],
        );
    }

    #[test]
    fn sub_small() {
        assert_eq!(
            BigUint::from_u128(13) - &BigUint::from_u128(5),
            BigUint::from_u128(8)
        );
    }

    #[test]
    fn sub_medium() {
        assert_eq!(
            BigUint::from_u128(13_000_000_000_000) - &BigUint::from_u128(5_000_000_000_000),
            BigUint::from_u128(8_000_000_000_000)
        );
    }

    #[test]
    fn sub_big() {
        assert_eq!(
            BigUint::from_be_bytes([13, 12, 11, 10]) - &BigUint::from_be_bytes([6, 7, 8, 9]),
            BigUint::from_be_bytes([7, 5, 3, 1])
        );
        assert_eq!(
            BigUint::from_be_bytes([13, 12, 11, 10]) - &BigUint::from_be_bytes([7, 8, 9]),
            BigUint::from_be_bytes([13, 5, 3, 1])
        );
        assert_eq!(
            BigUint::from_be_bytes([13, 12, 11, 10]) - &BigUint::from_be_bytes([13, 7, 8, 9]),
            BigUint::from_be_bytes([5, 3, 1])
        );
        assert_eq!(
            BigUint::from_be_bytes([13, 12, 11, 10]) - &BigUint::from_be_bytes([9]),
            BigUint::from_be_bytes([13, 12, 11, 1])
        );
        assert_eq!(
            BigUint::from_be_bytes([13, 12, 11, 10]) - &BigUint::from_be_bytes([13, 12, 11, 10]),
            BigUint::from_u128(0)
        );
        assert_eq!(
            BigUint::from_be_bytes([13, 12, 11, 10]) - &BigUint::from_be_bytes([11]),
            BigUint::from_be_bytes([13, 12, 10, 255])
        );
    }
}
