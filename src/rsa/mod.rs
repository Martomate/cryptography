mod asn1;
mod mgf;
mod oaep;
mod pad;

use asn1::{PrivateKeyInfo, SubjectPublicKeyInfo};
use gcd::Gcd;

pub use pad::RsaPadding;

use crate::{
    big::BigUint,
    pem::{asn1::Asn1, PEM},
};

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrivateKey {
    n: BigUint,
    d: BigUint,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey {
    n: BigUint,
    e: BigUint,
}

// typically e is 65537;

pub fn create_keys(p: BigUint, q: BigUint, e: BigUint) -> (PrivateKey, PublicKey) {
    let p: u128 = p.as_u128().unwrap();
    let q: u128 = q.as_u128().unwrap();
    let e: u128 = e.as_u128().unwrap();

    let n = p * q;

    let l = lcm(p - 1, q - 1);
    let d = inverse(e, l).unwrap();

    let n: BigUint = n.into();
    let d: BigUint = d.into();
    let e: BigUint = e.into();

    (
        PrivateKey { n: n.clone(), d },
        PublicKey { n: n.clone(), e },
    )
}

pub struct RsaEncryption {
    exponent: BigUint,
    modulo: BigUint,
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

impl TryFrom<PEM> for PrivateKey {
    type Error = String;

    fn try_from(pem: PEM) -> Result<Self, Self::Error> {
        if pem.label != "PRIVATE KEY" {
            return Err("must be a private key".to_string());
        }
        let asn = Asn1::try_from(pem.data.as_slice())?;
        let info = PrivateKeyInfo::try_from(asn)?;

        Ok(Self {
            n: info.private_key.modulus,
            d: info.private_key.private_exponent,
        })
    }
}

impl TryFrom<PEM> for PublicKey {
    type Error = String;

    fn try_from(pem: PEM) -> Result<Self, Self::Error> {
        if pem.label != "PUBLIC KEY" {
            return Err("must be a public key".to_string());
        }
        let asn = Asn1::try_from(pem.data.as_slice())?;
        let info = SubjectPublicKeyInfo::try_from(asn)?;

        Ok(Self {
            n: info.subject_public_key.modulus,
            e: info.subject_public_key.public_exponent,
        })
    }
}

impl RsaEncryption {
    pub fn encrypt_message(&self, plaintext: &[u8], padding: impl PaddingScheme) -> Vec<u8> {
        let m = padding.encode(b"", plaintext, (self.modulo.bits_used() - 1) as usize / 8);
        self.encrypt(BigUint::from_bytes(m)).as_bytes().to_owned()
    }

    pub fn encrypt(&self, m: BigUint) -> BigUint {
        pow_mod(&m, &self.exponent, &self.modulo)
    }

    pub fn decrypt_message(&self, ciphertext: &[u8], padding: impl PaddingScheme) -> Vec<u8> {
        let m = self.decrypt(BigUint::from_bytes(ciphertext));
        padding
            .decode(b"", m.as_bytes(), (self.modulo.bits_used() - 1) as usize / 8)
            .unwrap()
    }

    pub fn decrypt(&self, c: BigUint) -> BigUint {
        pow_mod(&c, &self.exponent, &self.modulo)
    }
}

fn mul_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    let mut a: u128 = a.as_u128().unwrap();
    let mut b: u128 = b.as_u128().unwrap();
    let m: u128 = m.as_u128().unwrap();

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
    BigUint::from(r)
}

fn pow_mod(a: &BigUint, p: &BigUint, m: &BigUint) -> BigUint {
    let mut a = a.clone();

    let mut r = BigUint::from(1);

    let steps = p.bits_used();
    for idx in 0..steps {
        if p.is_set(idx) {
            r = mul_mod(&r, &a, m);
        }
        a = mul_mod(&a, &a, m);
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
        assert_eq!(mul_mod(&BigUint::from(2), &BigUint::from(3), &BigUint::from(10000)), BigUint::from(6));
        assert_eq!(mul_mod(&BigUint::from(2), &BigUint::from(3), &BigUint::from(7)), BigUint::from(6));
        assert_eq!(mul_mod(&BigUint::from(2), &BigUint::from(3), &BigUint::from(3)), BigUint::from(0));
    }

    #[test]
    fn mul_mod_medium() {
        assert_eq!(mul_mod(&BigUint::from(2), &BigUint::from(30), &BigUint::from(1000000000000000)), BigUint::from(2 * 30));
        assert_eq!(mul_mod(&BigUint::from(2), &BigUint::from(30), &BigUint::from(10)), BigUint::from((2 * 30) % 10));
    }

    #[test]
    fn pow_mod_small() {
        assert_eq!(pow_mod(&2.into(), &3.into(), &10000.into()), BigUint::from(8));
        assert_eq!(pow_mod(&2.into(), &3.into(), &7.into()), BigUint::from(1));
        assert_eq!(pow_mod(&2.into(), &3.into(), &3.into()), BigUint::from(2));
    }

    #[test]
    fn pow_mod_medium() {
        assert_eq!(
            pow_mod(&2.into(), &30.into(), &1000000000000000.into()),
            (1 << 30).into()
        );
        assert_eq!(
            pow_mod(&2.into(), &30.into(), &10000.into()),
            ((1 << 30) % 10000).into()
        );
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

        let (private_key, public_key) =
            create_keys(BigUint::from(p), BigUint::from(q), BigUint::from(e));

        let d: u128 = private_key.d.as_u128().unwrap();
        let n: u128 = public_key.n.as_u128().unwrap();
        assert_eq!(public_key.e, BigUint::from(e));

        assert_eq!(n, p * q);
        assert_eq!((e * d) % lcm(p - 1, q - 1), 1);
    }

    #[test]
    fn more_small_keys() {
        let p = BigUint::from(61);
        let q = BigUint::from(53);
        let e = BigUint::from(17);

        let n = BigUint::from(61 * 53);
        let d = BigUint::from(413);

        let (pr, pb) = create_keys(p, q, e.clone());
        assert_eq!(pb.e, e);
        assert_eq!(pb.n, n);
        assert_eq!(pr.n, n);
        assert_eq!(pr.d, d);
    }

    struct NoPadding;

    impl PaddingScheme for NoPadding {
        fn encode(&self, _label: &[u8], message: &[u8], n_len: usize) -> Vec<u8> {
            let mut output = Vec::with_capacity(n_len);

            for _ in 0..n_len {
                output.push(message.len() as u8);
            }

            for (i, &m) in message.iter().enumerate() {
                output[i] = m;
            }

            dbg!(&output);

            output
        }
    
        fn decode(
            &self,
            _label: &[u8],
            encoded_message: &[u8],
            _n_len: usize,
        ) -> Result<Vec<u8>, &'static str> {
            let message_len = *encoded_message.last().unwrap() as usize;

            dbg!(&encoded_message);

            if message_len > encoded_message.len() {
                return Err("message too long");
            }

            Ok(encoded_message[0..message_len].to_vec())
        }
    }

    #[test]
    fn example_encrypt_e2e_small() {
        let p = BigUint::from(190238395574637701);
        let q = BigUint::from(725918707442996609);
        let e = BigUint::from(17);

        let (private_key, public_key) = create_keys(p, q, e);

        let plaintext = b"Hello World!";
        let ciphertext = RsaEncryption::from(public_key).encrypt_message(plaintext, NoPadding);
        let decrypted = RsaEncryption::from(private_key).decrypt_message(&ciphertext, NoPadding);

        assert_eq!(decrypted, plaintext);
    }
}
