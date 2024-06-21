use crate::sha::Sha256;

use super::{oaep::OaepPadding, PaddingScheme};

pub struct RsaPadding;

impl PaddingScheme for RsaPadding {
    fn encode(&self, label: &[u8], message: &[u8], n_len: usize) -> Vec<u8> {
        OaepPadding::new(Sha256).encode(label, message, n_len)
    }

    fn decode(
        &self,
        label: &[u8],
        encoded_message: &[u8],
        n_len: usize,
    ) -> Result<Vec<u8>, &'static str> {
        OaepPadding::new(Sha256).decode(label, encoded_message, n_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_is_the_reverse_of_encode() {
        let message = b"some message";
        let enc = RsaPadding.encode(b"abc", message, 123);
        let dec = RsaPadding.decode(b"abc", &enc, 123).unwrap();
        assert_eq!(dec, message.to_vec());
    }
}
