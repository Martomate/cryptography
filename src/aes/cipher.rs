use crate::{Block, BlockCipher};

use super::expander::AesKeyExpander;
use super::field::AesField;
use super::sbox::SBOX;

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
        for c in 0..4 {
            let i1 = c * 4;
            let i2 = c * 4 + 4;
            mix_column(&mut self.0[i1..i2]);
        }
    }
}

fn mix_column(col: &mut [u8]) {
    use AesField as F;

    let d0 = F::mul2(col[0]) ^ F::mul3(col[1]) ^ col[2] ^ col[3];
    let d1 = F::mul2(col[1]) ^ F::mul3(col[2]) ^ col[3] ^ col[0];
    let d2 = F::mul2(col[2]) ^ F::mul3(col[3]) ^ col[0] ^ col[1];
    let d3 = F::mul2(col[3]) ^ F::mul3(col[0]) ^ col[1] ^ col[2];

    col[0] = d0;
    col[1] = d1;
    col[2] = d2;
    col[3] = d3;
}

pub struct Aes {
    keys: Vec<Block<16>>,
    rounds: usize,
}

impl Aes {
    pub fn with_128_bit_key(key: Block<16>) -> Aes {
        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<16, 4>(key, 11);

        Aes { keys, rounds: 10 }
    }

    pub fn with_192_bit_key(key: Block<24>) -> Aes {
        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<24, 6>(key, 13);

        Aes { keys, rounds: 12 }
    }

    pub fn with_256_bit_key(key: Block<32>) -> Aes {
        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<32, 8>(key, 15);

        Aes { keys, rounds: 14 }
    }
}

impl BlockCipher<16> for Aes {
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
    use super::mix_column;

    #[test]
    fn mix_column_changes_the_column() {
        let original = [0xdb, 0x13, 0x53, 0x45];
        let mut col = original; // makes a copy
        mix_column(&mut col);
        assert_ne!(col, original);
    }

    #[test]
    fn mix_column_is_correct() {
        let examples = [
            (0xdb135345, 0x8e4da1bc),
            (0x01010101, 0x01010101),
            (0xc6c6c6c6, 0xc6c6c6c6),
            (0xd4d4d4d5, 0xd5d5d7d6),
            (0x2d26314c, 0x4d7ebdf8),
        ].map(|(l, r): (u32, u32)| (l.to_be_bytes(), r.to_be_bytes()));

        for (before, after) in examples {
            let mut col = before;
            mix_column(&mut col);
            assert_eq!(col, after);
        }
    }
}
