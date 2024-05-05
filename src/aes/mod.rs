use crate::{Block, BlockCipher};

use self::expander::AesKeyExpander;

mod expander;
mod field;
mod sbox;

struct State(Block<16>);

impl State {}

pub struct AES {
    keys: Vec<Block<16>>,
    rounds: usize,
}

impl AES {
    pub fn with_128_bit_key(key: Block<16>) -> AES {
        let rounds = 11;

        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<16, 4>(key, rounds);
        
        AES { keys, rounds }
    }
    
    pub fn with_192_bit_key(key: Block<24>) -> AES {
        let rounds = 13;

        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<24, 6>(key, rounds);
        
        AES { keys, rounds }
    }
    
    pub fn with_256_bit_key(key: Block<32>) -> AES {
        let rounds = 15;

        let expander = AesKeyExpander::new();
        let keys = expander.expand_key::<32, 8>(key, rounds);
        
        AES { keys, rounds }
    }
}

impl BlockCipher<16> for AES {
    fn encrypt(&self, plaintext: Block<16>) -> Block<16> {
        let state = State(plaintext);

        // todo: do operations

        state.0
    }
}

#[cfg(test)]
mod tests {}
