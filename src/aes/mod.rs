use crate::Block;

mod expander;
mod field;
mod sbox;
mod cipher;

use cipher::Aes;

pub fn aes_128(key: Block<16>) -> Aes {
    Aes::with_128_bit_key(key)
}

pub fn aes_192(key: Block<24>) -> Aes {
    Aes::with_192_bit_key(key)
}

pub fn aes_256(key: Block<32>) -> Aes {
    Aes::with_256_bit_key(key)
}
