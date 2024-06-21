mod mgf;
mod oaep;
mod pad;

use gcd::Gcd;

pub use pad::RsaPadding;

pub trait PaddingScheme {
    fn encode(&self, label: &[u8], message: &[u8], n_len: usize) -> Vec<u8>;

    fn decode(
        &self,
        label: &[u8],
        encoded_message: &[u8],
        n_len: usize,
    ) -> Result<Vec<u8>, &'static str>;
}

// TODO: the numbers below need to be much bigger than u128, so we need an array of bytes instead

pub struct PrivateKey {
    n: u128,
    d: u128,
}

pub struct PublicKey {
    n: u128,
    e: u128,
}

// typically e is 65537;

pub fn create_keys(p: u128, q: u128, e: u128) -> (PrivateKey, PublicKey) {
    let n = p * q;

    let l = lcm(p - 1, q - 1);
    let d = inverse(e, l).unwrap();

    (PrivateKey { n, d }, PublicKey { n, e })
}

pub struct RsaEncryption {
    exponent: u128,
    modulo: u128,
}

impl From<PrivateKey> for RsaEncryption {
    fn from(key: PrivateKey) -> Self {
        RsaEncryption {
            exponent: key.d,
            modulo: key.n,
        }
    }
}

impl From<PublicKey> for RsaEncryption {
    fn from(key: PublicKey) -> Self {
        RsaEncryption {
            exponent: key.e,
            modulo: key.n,
        }
    }
}

impl RsaEncryption {
    pub fn encrypt_message(&self, plaintext: &[u8], padding: impl PaddingScheme) -> Vec<u8> {
        let m = padding.encode(b"", plaintext, self.modulo.ilog2() as usize);
        self.encrypt(&m)
    }

    pub fn encrypt(&self, m: &[u8]) -> Vec<u8> {
        if m.len() > 16 {
            todo!("bigger numbers")
        } else {
            let mut bytes = [0; 16];
            bytes[(16 - m.len())..].copy_from_slice(m);
            let c = pow_mod(<u128>::from_be_bytes(bytes), self.exponent, self.modulo);
            c.to_be_bytes().into_iter().skip_while(|&n| n == 0).collect()
        }
    }

    pub fn decrypt_message(&self, ciphertext: &[u8], padding: impl PaddingScheme) -> Vec<u8> {
        let c = padding
            .decode(b"", ciphertext, self.modulo.ilog2() as usize)
            .unwrap();
        self.decrypt(&c)
    }

    pub fn decrypt(&self, c: &[u8]) -> Vec<u8> {
        if c.len() > 16 {
            todo!("bigger numbers")
        } else {
            let mut bytes = [0; 16];
            bytes[(16 - c.len())..].copy_from_slice(c);
            let m = pow_mod(<u128>::from_be_bytes(bytes), self.exponent, self.modulo);
            m.to_be_bytes().into_iter().skip_while(|&n| n == 0).collect()
        }
    }
}

fn mul_mod(mut a: u128, mut b: u128, m: u128) -> u128 {
    let mut r = 0;

    while b != 0 {
        if b & 1 != 0 {
            r += a;
            r %= m;
        }
        a <<= 1;
        a %= m;
        b >>= 1;
    }
    r
}

fn pow_mod(mut a: u128, mut p: u128, m: u128) -> u128 {
    let mut r = 1;

    while p != 0 {
        if p & 1 != 0 {
            r = mul_mod(r, a, m);
        }
        a = mul_mod(a, a, m);
        p >>= 1;
    }
    r
}

fn lcm(a: u128, b: u128) -> u128 {
    a * b / a.gcd(b)
}

fn inverse(a: u128, n: u128) -> Option<u128> {
    let (mut r, mut new_r) = (n, a);
    let (mut t, mut new_t) = (0_i128, 1_i128);

    while new_r != 0 {
        let q = r / new_r;
        (r, new_r) = (new_r, r - q * new_r);
        (t, new_t) = (new_t, t - (q as i128) * new_t);
    }

    if r != 1 {
        // not invertible since gcd != 1
        return None;
    }
    if t < 0 {
        t += n as i128;
    }
    Some(t as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_mod_small() {
        assert_eq!(mul_mod(2, 3, 10000), 6);
        assert_eq!(mul_mod(2, 3, 7), 6);
        assert_eq!(mul_mod(2, 3, 3), 0);
    }

    #[test]
    fn mul_mod_medium() {
        assert_eq!(mul_mod(2, 30, 1000000000000000), 2 * 30);
        assert_eq!(mul_mod(2, 30, 10), (2 * 30) % 10);
    }

    #[test]
    fn pow_mod_small() {
        assert_eq!(pow_mod(2, 3, 10000), 8);
        assert_eq!(pow_mod(2, 3, 7), 1);
        assert_eq!(pow_mod(2, 3, 3), 2);
    }

    #[test]
    fn pow_mod_medium() {
        assert_eq!(pow_mod(2, 30, 1000000000000000), 1 << 30);
        assert_eq!(pow_mod(2, 30, 10000), (1 << 30) % 10000);
    }

    #[test]
    fn inverse_mod_5() {
        assert_eq!(inverse(1, 5), Some(1));
        assert_eq!(inverse(2, 5), Some(3));
        assert_eq!(inverse(3, 5), Some(2));
        assert_eq!(inverse(4, 5), Some(4));
    }

    #[test]
    fn inverse_mod_8() {
        assert_eq!(inverse(1, 8), Some(1));
        assert_eq!(inverse(2, 8), None);
        assert_eq!(inverse(3, 8), Some(3));
        assert_eq!(inverse(4, 8), None);
        assert_eq!(inverse(5, 8), Some(5));
        assert_eq!(inverse(6, 8), None);
        assert_eq!(inverse(7, 8), Some(7));
    }

    #[test]
    fn small_keys() {
        let p = 7;
        let q = 11;
        let e = 17;

        let (private_key, public_key) = create_keys(p, q, e);

        let d = private_key.d;
        let n = public_key.n;
        assert_eq!(public_key.e, e);

        assert_eq!(n, p * q);
        assert_eq!((e * d) % lcm(p - 1, q - 1), 1);
    }

    #[test]
    fn more_small_keys() {
        let (pr, pb) = create_keys(61, 53, 17);
        assert_eq!(pb.e, 17);
        assert_eq!(pb.n, 61 * 53);
        assert_eq!(pr.n, 61 * 53);
        assert_eq!(pr.d, 413);
    }
}
