use crate::Block;

pub fn sha1_padding(src: &[u8], message_length: u64) -> (Block<64>, Option<Block<64>>) {
    let mut last = [0; 64];
    let mut extra = [0; 64];

    last[..src.len()].copy_from_slice(src);
    last[src.len()] = 0x80;

    if src.len() < 64 - 8 {
        last[(64 - 8)..].copy_from_slice(&(message_length * 8).to_be_bytes());
        (last, None)
    } else {
        extra[(64 - 8)..].copy_from_slice(&(message_length * 8).to_be_bytes());
        (last, Some(extra))
    }
}

#[cfg(test)]
mod tests {
    use super::sha1_padding;

    #[test]
    fn pad_empty_chunk_sets_1_bit() {
        let mut expected_chunk = [0; 64];
        expected_chunk[0] = 0x80;

        assert_eq!(sha1_padding(b"", 0), (expected_chunk, None));
    }

    #[test]
    fn pad_almost_full_chunk_creates_extra_chunk() {
        let mut expected_chunk = [0; 64];
        expected_chunk[60] = 0x80;

        assert_eq!(sha1_padding(&[0; 60], 0), (expected_chunk, Some([0; 64])));
    }

    #[test]
    fn pad_empty_chunk_includes_message_length_in_bits() {
        let mut expected_chunk = [0; 64];
        expected_chunk[0] = 0x80;
        expected_chunk[(64 - 8)..].copy_from_slice(&(123456789_u64 * 8).to_be_bytes());

        assert_eq!(sha1_padding(b"", 123456789), (expected_chunk, None));
    }

    #[test]
    fn pad_almost_full_chunk_includes_message_length_in_bits() {
        let mut expected_chunk = [0; 64];
        expected_chunk[60] = 0x80;

        let mut expected_extra_chunk = [0; 64];
        expected_extra_chunk[(64 - 8)..].copy_from_slice(&(123456789_u64 * 8).to_be_bytes());

        assert_eq!(
            sha1_padding(&[0; 60], 123456789),
            (expected_chunk, Some(expected_extra_chunk))
        );
    }
}
