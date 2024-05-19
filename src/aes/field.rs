pub struct AesField;

impl AesField {
    pub const fn mul2(n: u8) -> u8 {
        (n << 1) ^ (if n & 0x80 != 0 { 0x1b } else { 0 })
    }

    pub const fn mul3(n: u8) -> u8 {
        n ^ (n << 1) ^ (if n & 0x80 != 0 { 0x1b } else { 0 })
    }

    pub const fn div3(mut n: u8) -> u8 {
        n ^= n << 1;
        n ^= n << 2;
        n ^= n << 4;
        n ^= if n & 0x80 != 0 { 0x09 } else { 0 };
        n
    }
}

impl IntoIterator for AesField {
    type Item = (u8, u8);

    type IntoIter = AesFieldIterator;

    fn into_iter(self) -> Self::IntoIter {
        AesFieldIterator::start()
    }
}

pub struct AesFieldIterator {
    pub p: u8,
    pub q: u8, // inverse of p
}

impl AesFieldIterator {
    pub const fn start() -> Self {
        Self { p: 1, q: 1 }
    }

    pub const fn step(&self) -> Option<((u8, u8), (u8, u8))> {
        if self.p == 0 {
            // we're back at the start of the cycle
            return None;
        }

        let mut np = AesField::mul3(self.p);
        let nq = AesField::div3(self.q);

        if np == 1 {
            np = 0; // stop loop on next call
        }

        Some(((self.p, self.q), (np, nq)))
    }
}

impl Iterator for AesFieldIterator {
    type Item = (u8, u8);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(((n, inv), (np, nq))) = self.step() {
            self.p = np;
            self.q = nq;
            Some((n, inv))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::AesField;

    #[test]
    fn mul_and_div_are_inverses() {
        for n in 0..=255 {
            assert_eq!(AesField::mul3(AesField::div3(n)), n);
            assert_eq!(AesField::div3(AesField::mul3(n)), n);
        }
    }

    #[test]
    fn iterator_finds_all_values() {
        let mut ps = HashSet::new();
        let mut qs = HashSet::new();

        let mut iter = AesField.into_iter();
        for _ in 0..255 {
            let (p, q) = iter.next().unwrap();

            // ensure that we get new values
            assert!(ps.insert(p));
            assert!(qs.insert(q));
        }

        // ensure that we get no more values after this
        assert_eq!(iter.next(), None);

        // ensure that we get the right values
        assert_eq!(ps, HashSet::from_iter(1..=255));
        assert_eq!(qs, HashSet::from_iter(1..=255));
    }
}
