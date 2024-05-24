use crate::{Block, BlockCipher};

use super::expander::AesKeyExpander;
use super::field::AesField;
use super::sbox::SBOX;

struct State(Block<16>);

trait AesStep {
    fn forward(&self, state: &mut State);
    fn backward(&self, state: &mut State);
}

struct AddKey {
    key: Block<16>
}

impl AesStep for AddKey {
    fn forward(&self, state: &mut State) {
        for (i, b) in state.0.iter_mut().enumerate() {
            *b ^= self.key[i];
        }
    }

    fn backward(&self, state: &mut State) {
        // it's the same as forward in this case
        self.forward(state)
    }
}

struct Substitute;

impl AesStep for Substitute {
    fn forward(&self, state: &mut State) {
        for b in state.0.iter_mut() {
            *b = SBOX.forward[*b as usize];
        }
    }

    fn backward(&self, state: &mut State) {
        for b in state.0.iter_mut() {
            *b = SBOX.backward[*b as usize];
        }
    }
}

struct ShiftRows;

impl AesStep for ShiftRows {
    fn forward(&self, state: &mut State) {
        state.shift_row_one_step(1);

        state.shift_row_one_step(2);
        state.shift_row_one_step(2);

        state.shift_row_one_step(3);
        state.shift_row_one_step(3);
        state.shift_row_one_step(3);
    }

    fn backward(&self, state: &mut State) {
        state.shift_row_one_step(1);
        state.shift_row_one_step(1);
        state.shift_row_one_step(1);

        state.shift_row_one_step(2);
        state.shift_row_one_step(2);

        state.shift_row_one_step(3);
    }
}

struct MixColumns;

impl AesStep for MixColumns {
    fn forward(&self, state: &mut State) {
        for c in 0..4 {
            let i1 = c * 4;
            let i2 = c * 4 + 4;
            mix_column(&mut state.0[i1..i2]);
        }
    }

    fn backward(&self, state: &mut State) {
        for c in 0..4 {
            let i1 = c * 4;
            let i2 = c * 4 + 4;
            unmix_column(&mut state.0[i1..i2]);
        }
    }
}

impl State {
    fn shift_row_one_step(&mut self, row: usize) {
        let temp = self.0[row];
        for i in 0..3 {
            self.0[row + i * 4] = self.0[row + (i + 1) * 4];
        }
        self.0[row + 3 * 4] = temp;
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

fn unmix_column(col: &mut [u8]) {
    use AesField as F;

    let d0 = F::mul(col[0], 14) ^ F::mul(col[1], 11) ^ F::mul(col[2], 13) ^ F::mul(col[3], 9);
    let d1 = F::mul(col[1], 14) ^ F::mul(col[2], 11) ^ F::mul(col[3], 13) ^ F::mul(col[0], 9);
    let d2 = F::mul(col[2], 14) ^ F::mul(col[3], 11) ^ F::mul(col[0], 13) ^ F::mul(col[1], 9);
    let d3 = F::mul(col[3], 14) ^ F::mul(col[0], 11) ^ F::mul(col[1], 13) ^ F::mul(col[2], 9);

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

        AddKey{key: self.keys[0]}.forward(&mut state);

        for k in 1..self.rounds {
            Substitute.forward(&mut state);
            ShiftRows.forward(&mut state);
            MixColumns.forward(&mut state);
            AddKey{key: self.keys[k]}.forward(&mut state);
        }

        Substitute.forward(&mut state);
        ShiftRows.forward(&mut state);
        // Note: MixColumns should not be called here
        AddKey{key: self.keys[self.rounds]}.forward(&mut state);

        state.0
    }

    fn decrypt(&self, ciphertext: Block<16>) -> Block<16> {
        let mut state = State(ciphertext);

        AddKey{key: self.keys[self.rounds]}.backward(&mut state);
        // Note: MixColumns should not be called here
        ShiftRows.backward(&mut state);
        Substitute.backward(&mut state);

        for k in (1..self.rounds).rev() {
            AddKey{key: self.keys[k]}.backward(&mut state);
            MixColumns.backward(&mut state);
            ShiftRows.backward(&mut state);
            Substitute.backward(&mut state);
        }

        AddKey{key: self.keys[0]}.backward(&mut state);

        state.0
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::cipher::unmix_column;

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

    #[test]
    fn unmix_column_is_correct() {
        let examples = [
            (0x8e4da1bc, 0xdb135345),
            (0x01010101, 0x01010101),
            (0xc6c6c6c6, 0xc6c6c6c6),
            (0xd5d5d7d6, 0xd4d4d4d5),
            (0x4d7ebdf8, 0x2d26314c),
        ].map(|(l, r): (u32, u32)| (l.to_be_bytes(), r.to_be_bytes()));

        for (before, after) in examples {
            let mut col = before;
            unmix_column(&mut col);
            assert_eq!(col, after);
        }
    }
}
