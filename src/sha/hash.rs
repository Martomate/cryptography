use std::fmt::Display;

use hex::FromHex;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash160([u32; 5]);

impl Display for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}{:x}{:x}{:x}{:x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4])
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

impl From<[u32; 5]> for Hash160 {
    fn from(words: [u32; 5]) -> Self {
        Hash160(words)
    }
}

impl From<Hash160> for [u8; 160] {
    fn from(val: Hash160) -> Self {
        let mut res = [0; 160];
        for i in 0..5 {
            res[(4 * i)..(4 * i + 4)].copy_from_slice(&val.0[i].to_be_bytes());
        }
        res
    }
}
