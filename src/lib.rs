mod pad;

pub type Block<const N: usize> = [u8; N];

pub trait BlockCipher<const N: usize> {
    fn encrypt(&self, plaintext: Block<N>) -> Block<N>;
}

pub trait BlockCipherMode<const N: usize> {
    fn encrypt_block<C: BlockCipher<N>>(&mut self, cipher: &C, block: Block<N>) -> Block<N>;
}

pub struct BlockEncryption;

impl BlockEncryption {
    pub fn encrypt<C, M, const N: usize>(
        cipher: C,
        mut mode: M,
        plaintext: &[u8],
        mut output: impl FnMut(u8),
    ) where
        C: BlockCipher<N>,
        M: BlockCipherMode<N>,
    {
        let blocks = plaintext.chunks_exact(N);

        let last_part = blocks.remainder();
        let last_block = pad::BitPadding.pad(last_part);

        for block in blocks {
            let block = <[u8; N]>::try_from(block).unwrap();
            let output_block = mode.encrypt_block(&cipher, block);
            for b in output_block {
                output(b);
            }
        }

        let output_block = mode.encrypt_block(&cipher, last_block);
        for b in output_block {
            output(b);
        }
    }
}

#[cfg(test)]
#[allow(clippy::identity_op)]
#[allow(clippy::needless_range_loop)]
mod tests {
    use crate::{Block, BlockCipher, BlockCipherMode, BlockEncryption};

    struct SimpleCipher;
    impl BlockCipher<4> for SimpleCipher {
        fn encrypt(&self, plaintext: Block<4>) -> Block<4> {
            let mut ciphertext = plaintext;
            ciphertext.reverse();
            ciphertext
        }
    }

    struct NoopCipher<const N: usize>;

    impl<const N: usize> BlockCipher<N> for NoopCipher<N> {
        fn encrypt(&self, plaintext: Block<N>) -> Block<N> {
            plaintext
        }
    }

    struct SimpleCipherMode<const N: usize> {
        prev_output: [u8; N],
    }

    impl<const N: usize> BlockCipherMode<N> for SimpleCipherMode<N> {
        fn encrypt_block<C: BlockCipher<N>>(&mut self, cipher: &C, block: Block<N>) -> Block<N> {
            let mut input = block;
            for i in 0..N {
                input[i] ^= self.prev_output[i];
            }

            let output = cipher.encrypt(input);
            self.prev_output = output;

            output
        }
    }

    struct PassthroughMode<const N: usize>;

    impl<const N: usize> BlockCipherMode<N> for PassthroughMode<N> {
        fn encrypt_block<C: BlockCipher<N>>(&mut self, cipher: &C, block: Block<N>) -> Block<N> {
            cipher.encrypt(block)
        }
    }

    #[test]
    fn simple_block_cipher() {
        assert_eq!(SimpleCipher.encrypt([1, 3, 9, 4]), [4, 9, 3, 1]);
    }

    #[test]
    fn simple_cipher_mode() {
        let cipher = SimpleCipher;
        let mut mode = SimpleCipherMode {
            prev_output: [11, 12, 14, 13],
        };

        let output = mode.encrypt_block(&cipher, [1, 2, 4, 3]);
        let expected_output = SimpleCipher.encrypt([1 ^ 11, 2 ^ 12, 4 ^ 14, 3 ^ 13]);

        assert_eq!(output, expected_output);
        assert_eq!(mode.prev_output, output);
    }

    #[test]
    fn encrypting_misaligned_data_adds_padding() {
        let mut result = Vec::new();
        BlockEncryption::encrypt(NoopCipher::<4>, PassthroughMode::<4>, &[1, 2], |b| result.push(b));

        assert_eq!(&result, &[1, 2, 0x80, 0])
    }
    
    #[test]
    fn encrypting_aligned_data_adds_padding() {
        let mut result = Vec::new();
        BlockEncryption::encrypt(NoopCipher::<4>, PassthroughMode::<4>, &[1, 2, 4, 3], |b| result.push(b));

        assert_eq!(&result, &[1, 2, 4, 3, 0x80, 0, 0, 0])
    }

    #[test]
    fn encrypting_using_block_cipher() {
        let mut result = Vec::new();
        BlockEncryption::encrypt(SimpleCipher, PassthroughMode::<4>, &[1, 2, 4, 3, 7, 8], |b| result.push(b));

        assert_eq!(&result, &[3, 4, 2, 1, 0, 0x80, 8, 7])
    }

    #[test]
    fn encrypting_using_mode() {
        let iv = [9, 8, 7, 6];

        let plaintext = [1, 2, 4, 3, 7, 8];
        let plain1 = [1, 2, 4, 3];
        let plain2_padded = [7, 8, 0x80, 0];

        let cipher = NoopCipher::<4>;
        let mode = SimpleCipherMode {
            prev_output: iv,
        };
        
        let mut result = Vec::new();
        BlockEncryption::encrypt(cipher, mode, &plaintext, |b| result.push(b));

        let mut expected_output = Vec::with_capacity(8);
        {
            let cipher = NoopCipher::<4>;
            let mut mode = SimpleCipherMode {
                prev_output: iv,
            };
            expected_output.extend(&mode.encrypt_block(&cipher, plain1));
            expected_output.extend(&mode.encrypt_block(&cipher, plain2_padded));
        }
        assert_eq!(&result, &expected_output)
    }
}
