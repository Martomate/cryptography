use std::fmt::Display;

use hex::FromHex;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash160([u32; 5]);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash256([u32; 8]);

impl Display for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}{:x}{:x}{:x}{:x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4]
        )
    }
}

impl Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl FromHex for Hash160 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = <[u8; 20]>::from_hex(hex)?;

        let mut words = [0; 5];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            let chunk = <[u8; 4]>::try_from(chunk).unwrap();
            words[i] = u32::from_be_bytes(chunk);
        }

        Ok(Hash160(words))
    }
}

impl FromHex for Hash256 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::from_hex(hex)?;

        let mut words = [0; 8];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            let chunk = <[u8; 4]>::try_from(chunk).unwrap();
            words[i] = u32::from_be_bytes(chunk);
        }

        Ok(Hash256(words))
    }
}

impl From<[u32; 5]> for Hash160 {
    fn from(words: [u32; 5]) -> Self {
        Hash160(words)
    }
}

impl From<[u32; 8]> for Hash256 {
    fn from(words: [u32; 8]) -> Self {
        Hash256(words)
    }
}
