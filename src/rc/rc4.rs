use crate::StreamCipher;

pub struct KeyStream {
    state: [u8; 256],
    x: u8,
    y: u8,
}

impl KeyStream {
    pub fn new(key_data: &[u8]) -> Self {
        let mut state = [0_u8; 256];
        for i in 0..=255_u8 {
            state[i as usize] = i;
        }

        let mut j: u8 = 0;

        for i in 0..=255 {
            j = key_data[i % key_data.len()]
                .wrapping_add(state[i])
                .wrapping_add(j);
            state.swap(i, j as usize);
        }

        Self { state, x: 0, y: 0 }
    }

    fn next_key(&mut self) -> u8 {
        self.x = self.x.wrapping_add(1);
        self.y = self.state[self.x as usize].wrapping_add(self.y);
        self.state.swap(self.x as usize, self.y as usize);

        let xor_index = self.state[self.x as usize].wrapping_add(self.state[self.y as usize]);

        self.state[xor_index as usize]
    }

    pub fn encrypt(self, plaintext: &[u8]) -> Vec<u8> {
        StreamCipher::new(self)
            .encrypt(plaintext.iter().cloned())
            .collect::<Vec<_>>()
    }
    
    pub fn decrypt(self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }
}

impl Iterator for KeyStream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_key())
    }
}

#[cfg(test)]
mod tests {
    use crate::StreamCipher;

    use super::*;

    #[test]
    fn rc4_keys() {
        #[track_caller]
        fn check(key: &[u8], expected_key_stream_hex: &str) {
            let expected_key_stream = hex::decode(expected_key_stream_hex).unwrap();
            let key_stream = KeyStream::new(key)
                .take(expected_key_stream.len())
                .collect::<Vec<_>>();
            assert_eq!(key_stream, expected_key_stream);
        }

        check(b"Key", "EB9F7781B734CA72A719");
        check(b"Wiki", "6044DB6D41B7");
        check(b"Secret", "04D46B053CA87B59");
    }

    #[test]
    fn rc4_can_encrypt_split_messages() {
        let mut cipher = StreamCipher::new(KeyStream::new(b"Key"));
        let mut output = Vec::new();
        output.extend(cipher.encrypt(*b"Plaintext"));
        assert_eq!(output, 0xBBF316E8D940AF0AD3_u128.to_be_bytes()[7..]);

        let mut cipher = StreamCipher::new(KeyStream::new(b"Key"));
        let mut output = Vec::new();
        output.extend(cipher.encrypt(*b"Plain"));
        output.extend(cipher.encrypt(*b"text"));
        assert_eq!(output, 0xBBF316E8D940AF0AD3_u128.to_be_bytes()[7..]);
    }
}
