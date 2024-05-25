use crate::Block;

mod expander;
mod field;
mod sbox;
mod cipher;

pub use cipher::Aes;

pub struct Key128(Block<16>);
pub struct Key192(Block<24>);
pub struct Key256(Block<32>);

impl From<[u64; 2]> for Key128 {
    fn from(values: [u64; 2]) -> Self {
        Self(copy_u64s(values))
    }
}

impl From<[u64; 3]> for Key192 {
    fn from(values: [u64; 3]) -> Self {
        Self(copy_u64s(values))
    }
}

impl From<[u64; 4]> for Key256 {
    fn from(values: [u64; 4]) -> Self {
        Self(copy_u64s(values))
    }
}

impl From<Key128> for Aes {
    fn from(key: Key128) -> Self {
        Self::with_128_bit_key(key.0)
    }
}

impl From<Key192> for Aes {
    fn from(key: Key192) -> Self {
        Self::with_192_bit_key(key.0)
    }
}

impl From<Key256> for Aes {
    fn from(key: Key256) -> Self {
        Self::with_256_bit_key(key.0)
    }
}

fn copy_u64s<const V: usize, const N: usize>(values: [u64; V]) -> [u8; N] {
    let mut key = [0; N];
    for (i, v) in values.iter().enumerate() {
        key[(8 * i)..][..8].copy_from_slice(&v.to_be_bytes());
    }
    key
}
