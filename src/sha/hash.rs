use hex::FromHex;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash160([u8; 20]);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash224([u8; 28]);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash256([u8; 32]);

// From words

impl From<[u32; 5]> for Hash160 {
    fn from(words: [u32; 5]) -> Self {
        Hash160(words_to_bytes(words))
    }
}

impl From<[u32; 7]> for Hash224 {
    fn from(words: [u32; 7]) -> Self {
        Hash224(words_to_bytes(words))
    }
}

impl From<[u32; 8]> for Hash256 {
    fn from(words: [u32; 8]) -> Self {
        Hash256(words_to_bytes(words))
    }
}

// To words

impl From<Hash160> for [u32; 5] {
    fn from(hash: Hash160) -> Self {
        bytes_to_words(hash.0)
    }
}

impl From<Hash224> for [u32; 7] {
    fn from(hash: Hash224) -> Self {
        bytes_to_words(hash.0)
    }
}

impl From<Hash256> for [u32; 8] {
    fn from(hash: Hash256) -> Self {
        bytes_to_words(hash.0)
    }
}

// From hex

impl FromHex for Hash160 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        <[u8; 20]>::from_hex(hex).map(Hash160)
    }
}

impl FromHex for Hash224 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        <[u8; 28]>::from_hex(hex).map(Hash224)
    }
}

impl FromHex for Hash256 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        <[u8; 32]>::from_hex(hex).map(Hash256)
    }
}

// Helpers

fn words_to_bytes<const W: usize, const B: usize>(words: [u32; W]) -> [u8; B] {
    let mut bytes = [0; B];
    for (i, w) in words.into_iter().enumerate() {
        bytes[(4 * i)..][..4].copy_from_slice(&w.to_be_bytes());
    }
    bytes
}

fn bytes_to_words<const B: usize, const W: usize>(bytes: [u8; B]) -> [u32; W] {
    let mut words = [0; W];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let chunk = <[u8; 4]>::try_from(chunk).unwrap();
        words[i] = u32::from_be_bytes(chunk);
    }
    words
}
