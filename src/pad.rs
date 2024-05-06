use crate::Block;

pub struct BitPadding<const N: usize>;

impl<const N: usize> BitPadding<N> {
    pub fn pad(&self, partial_block: &[u8]) -> Block<N> {
        if partial_block.len() >= N {
            panic!("input block must be shorter than N");
        }

        let mut new_block = [0; N];
        new_block[..partial_block.len()].copy_from_slice(partial_block);
        new_block[partial_block.len()] = 0x80;
        new_block
    }

    pub fn unpad(&self, last_block: Block<N>) -> (Block<N>, usize) {
        let len = last_block
            .iter()
            .rposition(|&b| b == 0x80)
            .expect("missing marker byte (0x80)");
        let mut block = last_block;
        block[len..].fill(0);
        (block, len)
    }
}

pub struct PkcsPadding<const N: usize>;

impl<const N: usize> PkcsPadding<N> {
    pub fn pad(&self, partial_block: &[u8]) -> Block<N> {
        let len = partial_block.len();
        if len >= N {
            panic!("input block must be shorter than N");
        }

        let mut new_block = [0; N];
        new_block[..len].copy_from_slice(partial_block);
        for b in &mut new_block[len..N] {
            *b = (N - len) as u8;
        }
        new_block
    }
}

#[cfg(test)]
mod tests {
    mod bit {
        use crate::pad::BitPadding;

        #[test]
        fn pad_empty_block() {
            assert_eq!(BitPadding.pad(&[]), [0x80, 0, 0, 0]);
        }

        #[test]
        fn pad_partial_block() {
            assert_eq!(BitPadding.pad(&[1, 2, 3]), [1, 2, 3, 0x80]);
        }

        #[test]
        #[should_panic]
        fn pad_full_block_should_panic() {
            BitPadding::<4>.pad(&[1, 2, 3, 4]);
        }

        #[test]
        #[should_panic]
        fn pad_overfull_block_should_panic() {
            BitPadding::<4>.pad(&[1, 2, 3, 4, 5]);
        }

        #[test]
        fn unpad_empty_block() {
            assert_eq!(BitPadding.unpad([0x80, 0, 0, 0]), ([0, 0, 0, 0], 0));
        }

        #[test]
        fn unpad_partial_block() {
            assert_eq!(BitPadding.unpad([1, 2, 3, 0x80]), ([1, 2, 3, 0], 3));
        }

        #[test]
        #[should_panic]
        fn unpad_empty_block_with_missing_end_marker() {
            BitPadding::<4>.unpad([0, 0, 0, 0]);
        }

        #[test]
        #[should_panic]
        fn unpad_full_block_with_missing_end_marker() {
            BitPadding::<4>.unpad([1, 2, 3, 4]);
        }
    }

    mod pkcs {
        use crate::pad::PkcsPadding;

        #[test]
        fn pad_empty_block() {
            assert_eq!(PkcsPadding.pad(&[]), [4, 4, 4, 4]);
        }

        #[test]
        fn pad_partial_block() {
            assert_eq!(PkcsPadding.pad(&[1, 2, 3]), [1, 2, 3, 1]);
        }

        #[test]
        #[should_panic]
        fn pad_full_block_should_panic() {
            PkcsPadding::<4>.pad(&[1, 2, 3, 4]);
        }

        #[test]
        #[should_panic]
        fn pad_overfull_block_should_panic() {
            PkcsPadding::<4>.pad(&[1, 2, 3, 4, 5]);
        }
    }
}
