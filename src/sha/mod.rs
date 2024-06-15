use std::fmt::{Debug, Display};

mod pad;

#[derive(PartialEq, Eq, Clone)]
pub struct Hash160([u32; 5]);

impl Display for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}{:x}{:x}{:x}{:x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4])
    }
}

impl Debug for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}_{:x}_{:x}_{:x}_{:x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4])
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

fn process_chunk(hash: &mut Hash160, chunk: [u8; 64]) {
    let mut w = [0_u32; 80];
    for i in 0..16 {
        let word = <[u8; 4]>::try_from(&chunk[(4*i)..][..4]).unwrap();
        w[i] = u32::from_be_bytes(word);
    }
    for i in 16..80 {
        w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = hash.0; // this will copy

    for (i, &w) in w.iter().enumerate() {
        let (k, f) = match i {
            0..=19 =>  (0x5A827999, (b & c) | ((!b) & d)),
            20..=39 => (0x6ED9EBA1, b ^ c ^ d),
            40..=59 => (0x8F1BBCDC, (b & c) | (b & d) | (c & d)),
            60..=79 => (0xCA62C1D6, b ^ c ^ d),
            _ => unreachable!()
        };

        let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    hash.0[0] = hash.0[0].wrapping_add(a);
    hash.0[1] = hash.0[1].wrapping_add(b);
    hash.0[2] = hash.0[2].wrapping_add(c);
    hash.0[3] = hash.0[3].wrapping_add(d);
    hash.0[4] = hash.0[4].wrapping_add(e);
}

pub fn sha1(message: &[u8]) -> Hash160 {
    let chunks = message.chunks_exact(64);
    let remaining_bytes = chunks.remainder();
    let (last_chunk, extra_chunk) = pad::sha1_padding(remaining_bytes, message.len() as u64);

    let mut hash = Hash160::from([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);

    for chunk in chunks {
        let chunk = <[u8; 64]>::try_from(chunk).unwrap();
        process_chunk(&mut hash, chunk);
    }
    process_chunk(&mut hash, last_chunk);
    if let Some(extra_chunk) = extra_chunk {
        process_chunk(&mut hash, extra_chunk);
    }

    hash
}

#[cfg(test)]
mod tests {}
