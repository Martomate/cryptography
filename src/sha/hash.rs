use hex::FromHex;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HashValue<const N: usize>([u8; N]);

pub type Hash160 = HashValue<20>;
pub type Hash224 = HashValue<28>;
pub type Hash256 = HashValue<32>;
pub type Hash384 = HashValue<48>;
pub type Hash512 = HashValue<64>;

// From words

impl From<[u32; 5]> for Hash160 {
    fn from(words: [u32; 5]) -> Self {
        HashValue(u32s_to_bytes(words))
    }
}

impl From<[u32; 7]> for Hash224 {
    fn from(words: [u32; 7]) -> Self {
        HashValue(u32s_to_bytes(words))
    }
}

impl From<[u32; 8]> for Hash256 {
    fn from(words: [u32; 8]) -> Self {
        HashValue(u32s_to_bytes(words))
    }
}

impl From<[u64; 6]> for Hash384 {
    fn from(words: [u64; 6]) -> Self {
        HashValue(u64s_to_bytes(words))
    }
}

impl From<[u64; 8]> for Hash512 {
    fn from(words: [u64; 8]) -> Self {
        HashValue(u64s_to_bytes(words))
    }
}

// To words

impl From<Hash160> for [u32; 5] {
    fn from(hash: Hash160) -> Self {
        bytes_to_u32s(hash.0)
    }
}

impl From<Hash224> for [u32; 7] {
    fn from(hash: Hash224) -> Self {
        bytes_to_u32s(hash.0)
    }
}

impl From<Hash256> for [u32; 8] {
    fn from(hash: Hash256) -> Self {
        bytes_to_u32s(hash.0)
    }
}

impl From<Hash384> for [u64; 6] {
    fn from(hash: Hash384) -> Self {
        bytes_to_u64s(hash.0)
    }
}

impl From<Hash512> for [u64; 8] {
    fn from(hash: Hash512) -> Self {
        bytes_to_u64s(hash.0)
    }
}

// To bytes

impl<const N: usize> From<HashValue<N>> for [u8; N] {
    fn from(value: HashValue<N>) -> Self {
        value.0
    }
}

// From hex

impl<const N: usize> FromHex for HashValue<N> {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = Vec::<u8>::from_hex(hex)?;
        if bytes.len() != N {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        Ok(HashValue(<[u8; N]>::try_from(bytes).unwrap()))
    }
}

// Helpers

fn u32s_to_bytes<const W: usize, const B: usize>(words: [u32; W]) -> [u8; B] {
    let mut bytes = [0; B];
    for (i, w) in words.into_iter().enumerate() {
        bytes[(4 * i)..][..4].copy_from_slice(&w.to_be_bytes());
    }
    bytes
}

fn u64s_to_bytes<const W: usize, const B: usize>(words: [u64; W]) -> [u8; B] {
    let mut bytes = [0; B];
    for (i, w) in words.into_iter().enumerate() {
        bytes[(8 * i)..][..8].copy_from_slice(&w.to_be_bytes());
    }
    bytes
}

fn bytes_to_u32s<const B: usize, const W: usize>(bytes: [u8; B]) -> [u32; W] {
    let mut words = [0; W];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let chunk = <[u8; 4]>::try_from(chunk).unwrap();
        words[i] = u32::from_be_bytes(chunk);
    }
    words
}

fn bytes_to_u64s<const B: usize, const W: usize>(bytes: [u8; B]) -> [u64; W] {
    let mut words = [0; W];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let chunk = <[u8; 8]>::try_from(chunk).unwrap();
        words[i] = u64::from_be_bytes(chunk);
    }
    words
}
