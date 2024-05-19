use crate::{Block, BlockCipher};

use self::{
    expander::AesKeyExpander,
    field::AesField,
    sbox::SBOX,
};

mod expander;
mod field;
mod sbox;

struct State(Block<16>);

impl State {
    fn add_key(&mut self, key: &Block<16>) {
        for (i, b) in self.0.iter_mut().enumerate() {
            *b ^= key[i];
        }
    }

    fn substitute(&mut self) {
        for b in self.0.iter_mut() {
            *b = SBOX[*b];
        }
    }

    fn shift_rows(&mut self) {
        self.shift_row_one_step(1);

        self.shift_row_one_step(2);
        self.shift_row_one_step(2);

        self.shift_row_one_step(3);
        self.shift_row_one_step(3);
        self.shift_row_one_step(3);
    }

    fn shift_row_one_step(&mut self, row: usize) {
        let temp = self.0[row];
        for i in 0..3 {
            self.0[row + i * 4] = self.0[row + (i + 1) * 4];
        }
        self.0[row + 3 * 4] = temp;
    }

    fn mix_columns(&mut self) {
        for i in 0..4 {
            self.mix_column(i);
        }
    }

    fn mix_column(&mut self, c: usize) {
        use AesField as F;

        let i1 = c * 4;
        let i2 = c * 4 + 4;
        let col = &mut self.0[i1..i2];

        let d0 = F::mul2(col[0]) ^ F::mul3(col[1]) ^ col[2] ^ col[3];
        let d1 = F::mul2(col[1]) ^ F::mul3(col[2]) ^ col[3] ^ col[0];
        let d2 = F::mul2(col[2]) ^ F::mul3(col[3]) ^ col[0] ^ col[1];
        let d3 = F::mul2(col[3]) ^ F::mul3(col[0]) ^ col[1] ^ col[2];

        col[0] = d0;
        col[1] = d1;
        col[2] = d2;
        col[3] = d3;
    }
}

pub struct AES {
    keys: Vec<Block<16>>,
    rounds: usize,
}

impl AES {
    pub fn with_128_bit_key(key: Block<16>) -> AES {
        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<16, 4>(key, 11);

        AES { keys, rounds: 10 }
    }

    pub fn with_192_bit_key(key: Block<24>) -> AES {
        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<24, 6>(key, 13);

        AES { keys, rounds: 12 }
    }

    pub fn with_256_bit_key(key: Block<32>) -> AES {
        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<32, 8>(key, 15);

        AES { keys, rounds: 14 }
    }
}

impl BlockCipher<16> for AES {
    fn encrypt(&self, plaintext: Block<16>) -> Block<16> {
        let mut state = State(plaintext);

        state.add_key(&self.keys[0]);

        for k in 1..self.rounds {
            state.substitute();
            state.shift_rows();
            state.mix_columns();
            state.add_key(&self.keys[k]);
        }

        state.substitute();
        state.shift_rows();
        // Note: mix_columns should not be called here
        state.add_key(&self.keys[self.rounds]);

        state.0
    }
}

#[cfg(test)]
mod tests {
    use crate::{Block, BlockEncryption, EcbMode};

    use super::{State, AES};

    #[test]
    fn mix_column_changes_the_column() {
        let mut state = [0; 16];
        state[0..4].copy_from_slice(&[0xdb, 0x13, 0x53, 0x45]);

        let mut state = State(state);
        state.mix_column(0);

        assert_ne!(state.0[0..4], [0xdb, 0x13, 0x53, 0x45]);
    }

    #[test]
    fn mix_column_is_correct() {
        let examples = [
            ([0xdb, 0x13, 0x53, 0x45], [0x8e, 0x4d, 0xa1, 0xbc]),
            ([0x01, 0x01, 0x01, 0x01], [0x01, 0x01, 0x01, 0x01]),
            ([0xc6, 0xc6, 0xc6, 0xc6], [0xc6, 0xc6, 0xc6, 0xc6]),
            ([0xd4, 0xd4, 0xd4, 0xd5], [0xd5, 0xd5, 0xd7, 0xd6]),
            ([0x2d, 0x26, 0x31, 0x4c], [0x4d, 0x7e, 0xbd, 0xf8]),
        ];

        for (before, after) in examples {
            let mut state = [0; 16];
            state[0..4].copy_from_slice(&before);

            let mut state = State(state);
            state.mix_column(0);

            assert_eq!(state.0[0..4], after);
        }
    }

    #[test]
    fn aes_128_basic_with_zero_key() {
        let key: Block<16> = [0; 16];

        let cipher = AES::with_128_bit_key(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext[..16],
            &[
                0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
                0x63, 0xe3,
            ]
        );
    }

    #[test]
    fn aes_128_basic_with_actual_key() {
        let key: Block<16> = 0x12345678901234567890123456789012u128.to_be_bytes();

        let cipher = AES::with_128_bit_key(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext[..16],
            &0x6137ea77f33803f0b809f6aa5cf86616u128.to_be_bytes()
        );
        assert_eq!(
            &ciphertext[16..32],
            &0x4923331c01b6fe7d220360df6a7f6fb2u128.to_be_bytes()
        );
    }
}
