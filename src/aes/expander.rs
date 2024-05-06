use std::ops::{BitXor, Deref, DerefMut};

use crate::Block;

use super::{field::AesField, sbox::Sbox};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Word(Block<4>);

impl Deref for Word {
    type Target = Block<4>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Word {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl BitXor for Word {
    type Output = Word;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let Word([a0, a1, a2, a3]) = self;
        let Word([b0, b1, b2, b3]) = rhs;
        Word([a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3])
    }
}

pub struct AesKeyExpander {
    sbox: Sbox,
    rcon: [Word; 11],
}

impl AesKeyExpander {
    pub fn new() -> AesKeyExpander {
        AesKeyExpander {
            sbox: Sbox::calculate(),
            rcon: Self::calculate_round_constants().map(|rc| Word([rc, 0, 0, 0])),
        }
    }

    pub fn expand_key<const K: usize, const W: usize>(&self, key: Block<K>, num_keys: usize) -> Vec<Block<16>> {
        let key_words: Vec<Word> = key.chunks_exact(4).map(|bytes| Word(bytes.try_into().unwrap())).collect();
        let key_array = key_words.as_slice().try_into().unwrap();

        let result = self.expand_key_using_words::<W>(key_array, num_keys);
        
        let mut expanded_keys: Vec<Block<16>> = Vec::with_capacity(16 * num_keys);
        for words in result.chunks(4) {
            let mut block: Block<16> = Default::default();
            for wi in 0..4 {
                for bi in 0..4 {
                    block[wi * 4 + bi] = words[wi][bi];
                }
            }
            expanded_keys.push(block);
        }

        expanded_keys
    }

    pub fn expand_key_using_words<const N: usize>(&self, key: [Word; N], num_keys: usize) -> Vec<Word> {
        let mut w = Vec::with_capacity(16 * num_keys);
        for i in 0..(4 * num_keys) {
            let v = if i < N {
                key[i]
            } else if i % N == 0 {
                w[i - N] ^ self.substitute_word(Self::rotate_word(w[i - 1])) ^ self.rcon[i / N]
            } else if N > 6 && i % N == 4 {
                w[i - N] ^ self.substitute_word(w[i - 1])
            } else {
                w[i - N] ^ w[i - 1]
            };

            w.push(v);
        }
        w
    }

    fn calculate_round_constants<const L: usize>() -> [u8; L] {
        let mut result = [0; L];

        let mut n = 1;
        for r in result[1..].iter_mut() {
            *r = n;
            n = AesField::mul2(n);
        }

        result
    }

    fn rotate_word(w: Word) -> Word {
        Word([w[1], w[2], w[3], w[0]])
    }

    fn substitute_word(&self, w: Word) -> Word {
        Word([
            self.sbox[w[0]],
            self.sbox[w[1]],
            self.sbox[w[2]],
            self.sbox[w[3]],
        ])
    }
}

impl Default for AesKeyExpander {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::sbox::Sbox;

    use super::{AesKeyExpander, Word};

    fn make_key<const N: usize>(f: impl Fn(u8, u8) -> u8) -> [Word; N] {
        core::array::from_fn(|i| Word(core::array::from_fn(|j| f(i as u8, j as u8))))
    }

    #[test]
    fn rotate_word() {
        assert_eq!(
            AesKeyExpander::rotate_word(Word([1, 2, 3, 4])),
            Word([2, 3, 4, 1])
        );
    }

    #[test]
    fn substitute_word() {
        let expander = AesKeyExpander::new();
        let actual = expander.substitute_word(Word([1, 2, 3, 4]));

        let sbox = Sbox::calculate();
        let expected = Word([sbox[1], sbox[2], sbox[3], sbox[4]]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn round_constants() {
        assert_eq!(
            AesKeyExpander::calculate_round_constants(),
            [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        )
    }

    #[test]
    fn expand_key() {
        let expander = AesKeyExpander::new();
        let key = make_key::<6>(|i, j| 10 * i + j);
        let exp = expander.expand_key_using_words(key, 5);

        // if should create 5 new keys with 4 words each (128 bit)
        assert_eq!(exp.len(), 20);

        // the first bytes should come from the key
        for i in 0..6 {
            assert_eq!(exp[i], key[i]);
        }

        // the following bytes should NOT come from the key
        for i in 6..12 {
            assert_ne!(exp[i], key[i-6]);
        }

        // they should also not be zero
        for &e in &exp[6..] {
            assert_ne!(e, Word([0, 0, 0, 0]));
        }
    }
}
