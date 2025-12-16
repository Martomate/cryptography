use std::{
    cmp::Ordering,
    ops::{AddAssign, RemAssign, ShlAssign, ShrAssign, Sub, SubAssign},
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

        Self {
            bytes: bytes.iter().rev().cloned().collect(),
        }
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
            return Self { bytes: vec![] };
        }

        let bytes = value.to_le_bytes();
        let num_bytes = bytes.iter().rposition(|&n| n != 0).unwrap() + 1;
        Self {
            bytes: bytes[..num_bytes].to_owned(),
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

    fn trim_trailing_zeroes(&mut self) {
        while self.bytes.last().filter(|&a| *a == 0).is_some() {
            self.bytes.pop();
        }
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

impl AddAssign<u8> for BigUint {
    fn add_assign(&mut self, rhs: u8) {
        self.bytes.push(0); // in case of overflow

        let mut carry = rhs as u16;

        for b in &mut self.bytes {
            if carry == 0 {
                break;
            }
            let sum = carry + *b as u16;
            *b = (sum & 0xff) as u8;
            carry = (sum >> 8) & 0xff;
        }

        self.trim_trailing_zeroes()
    }
}

impl AddAssign<&BigUint> for BigUint {
    fn add_assign(&mut self, rhs: &BigUint) {
        while rhs.bytes.len() > self.bytes.len() {
            self.bytes.push(0);
        }
        self.bytes.push(0); // in case of overflow

        let l = &mut self.bytes;
        let r = &rhs.bytes;

        let l_len = l.len();
        let r_len = r.len();

        let mut carry = 0_u16;

        for i in 0..l_len - 1 {
            let mut sum = carry;
            sum += l[i] as u16;
            if i < r_len {
                sum += r[i] as u16;
            }
            l[i] = (sum & 0xff) as u8;
            carry = (sum >> 8) & 0xff;
        }
        l[l_len - 1] = carry as u8;

        self.trim_trailing_zeroes()
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

impl SubAssign<&BigUint> for BigUint {
    fn sub_assign(&mut self, rhs: &BigUint) {
        let curr_bits_used = self.bits_used();

        // ensure there is enough space for the upcoming addition
        let mut inv = Vec::with_capacity(self.bytes.len() + 1);

        let offset = inv.capacity() - rhs.bytes.len();
        for i in 0..rhs.bytes.len() {
            inv.push(!rhs.bytes[i]);
        }
        for _ in 0..offset {
            inv.push(!0);
        }
        let mut inv = BigUint { bytes: inv };
        inv.trim_trailing_zeroes();

        *self += 1;
        *self += &inv;

        for i in curr_bits_used..self.bits_used() {
            self.update(i, false);
        }
        self.trim_trailing_zeroes()
    }
}

impl Sub<&BigUint> for BigUint {
    type Output = BigUint;

    fn sub(self, rhs: &BigUint) -> Self::Output {
        let mut res = self.clone();
        res -= rhs;
        res
    }
}

impl RemAssign<&BigUint> for BigUint {
    fn rem_assign(&mut self, rhs: &BigUint) {
        if rhs.bits_used() > self.bits_used() {
            return;
        }

        let d = self.bits_used() - rhs.bits_used();

        let mut m = rhs.clone();
        m <<= d;

        for _ in (0..=d).rev() {
            if m <= *self {
                *self -= &m;
            }
            m >>= 1;
        }
    }
}

impl ShlAssign<u32> for BigUint {
    fn shl_assign(&mut self, mut rhs: u32) {
        let steps = rhs / 8; // save whole bytes for later
        rhs -= steps * 8;

        if rhs > 0 {
            self.bytes.push(0); // in case of overflow
            let mut carry = 0_u8;

            for b in &mut self.bytes {
                let res = carry | *b << rhs;
                carry = *b >> (8 - rhs);
                *b = res;
            }

            self.trim_trailing_zeroes()
        }

        if steps > 0 {
            self.bytes
                .splice(0..0, std::iter::repeat_n(0, steps as usize));
        }
    }
}

impl ShrAssign<u32> for BigUint {
    fn shr_assign(&mut self, mut rhs: u32) {
        if rhs >= 8 {
            let steps = rhs / 8;

            self.bytes.splice(0..steps as usize, []);

            rhs -= steps * 8;
        }

        if rhs > 0 {
            let mut carry = 0_u8;
            for i in (0..self.bytes.len()).rev() {
                let res = carry | (self.bytes[i] >> rhs);
                carry = self.bytes[i] << (8 - rhs);
                self.bytes[i] = res;
            }
            self.trim_trailing_zeroes();
        }
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
